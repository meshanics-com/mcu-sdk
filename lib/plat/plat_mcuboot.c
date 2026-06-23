/*
 * plat_mcuboot.c - the firmware install side for the ESP32-S3 agent.
 * Streams the image into the MCUboot secondary slot, verifies it hashes to the
 * manifest digest, requests a revertable swap, and exposes the boot-confirm
 * primitives the agent uses to confirm a healthy image (or let MCUboot revert a
 * bad one). The A/B swap + image-confirm path is the one proven on metal by
 * agent/mcu/mcuboot-test; the download/verify decisions are host-proven in
 * agent/mcu/ota.
 */
#include "plat.h"
#include "plat_net.h"

#include <zephyr/kernel.h>
#include <zephyr/dfu/flash_img.h>
#include <zephyr/dfu/mcuboot.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/logging/log.h>

#include <psa/crypto.h>
#include <string.h>

LOG_MODULE_REGISTER(plat_mcuboot, LOG_LEVEL_INF);

/* hex_nibble returns 0-15 for a hex digit, or -1 for a non-hex char. */
static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

/* hex32 parses exactly 64 hex chars into a 32-byte buffer. Returns 0 on success.
 * Self-contained so the installer carries no extra util dependency. */
static int hex32(const char *hex, uint8_t out[32])
{
	for (int i = 0; i < 32; i++) {
		int hi = hex_nibble(hex[2 * i]);
		int lo = hex_nibble(hex[2 * i + 1]);
		if (hi < 0 || lo < 0) {
			return -1;
		}
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return 0;
}

int plat_image_confirmed(void)
{
	return boot_is_img_confirmed() ? 1 : 0;
}

int plat_confirm_image(void)
{
	int rc = boot_write_img_confirmed();
	if (rc) {
		LOG_ERR("boot_write_img_confirmed failed (%d)", rc);
	}
	return rc;
}

void plat_reboot(void)
{
	sys_reboot(SYS_REBOOT_COLD);
}

/* verify_slot_sha256 reads the first `size` bytes back from the secondary slot
 * and checks they hash to `expect`. Uses PSA SHA-256 (already initialised for
 * TLS), so it needs no extra crypto config and cannot clash with the vendored
 * Ed25519 tinycrypt. This is the manifest-digest check; MCUboot's image signature
 * verification at boot is the ultimate integrity gate. */
static int verify_slot_sha256(uint64_t size, const uint8_t expect[32])
{
	const struct flash_area *fa;
	if (flash_area_open(FIXED_PARTITION_ID(slot1_partition), &fa) != 0) {
		return -1;
	}
	psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
	int rc = -1;
	if (psa_hash_setup(&op, PSA_ALG_SHA_256) != PSA_SUCCESS) {
		goto out;
	}
	static uint8_t rb[512];
	uint64_t off = 0;
	while (off < size) {
		size_t n = (size - off) < sizeof(rb) ? (size_t)(size - off) : sizeof(rb);
		if (flash_area_read(fa, (off_t)off, rb, n) != 0) {
			(void)psa_hash_abort(&op);
			goto out;
		}
		if (psa_hash_update(&op, rb, n) != PSA_SUCCESS) {
			(void)psa_hash_abort(&op);
			goto out;
		}
		off += n;
	}
	uint8_t out[32];
	size_t olen = 0;
	if (psa_hash_finish(&op, out, sizeof(out), &olen) != PSA_SUCCESS || olen != 32) {
		goto out;
	}
	rc = (memcmp(out, expect, 32) == 0) ? 0 : -1;
out:
	flash_area_close(fa);
	return rc;
}

/* stage_sink writes each streamed firmware chunk into the MCUboot secondary slot,
 * flushing flash_img's internal buffer on the final chunk. */
static int stage_sink(const uint8_t *data, size_t len, int last, void *vctx)
{
	struct flash_img_context *ic = vctx;
	int rc = flash_img_buffered_write(ic, data, len, last != 0);
	if (rc != 0) {
		LOG_ERR("flash write rc=%d after %zu bytes (len=%zu last=%d)",
			rc, (size_t)flash_img_bytes_written(ic), len, last);
	}
	return rc;
}

int plat_stage_image(const char *sha256_hex, uint64_t size)
{
	if (size == 0) {
		return -1;
	}
	uint8_t expect[32];
	if (sha256_hex == NULL || hex32(sha256_hex, expect) != 0) {
		LOG_ERR("bad sha256 hex");
		return -1;
	}

	struct flash_img_context ctx;
	if (flash_img_init(&ctx) != 0) {
		LOG_ERR("flash_img_init failed");
		return -1;
	}

	/* Stream the image into slot B over a single mTLS connection. */
	int rc = plat_net_firmware_download(size, stage_sink, &ctx);
	if (rc != 0) {
		LOG_ERR("firmware download/flash failed rc=%d (-3 net, -4 http, -5 flash, -1 short)", rc);
		return -1;
	}

	/* Verify the written image hashes to the digest the verified manifest named,
	 * before we ever ask MCUboot to boot it. */
	if (verify_slot_sha256(size, expect) != 0) {
		LOG_ERR("staged image digest mismatch - refusing");
		return -1;
	}
	LOG_INF("image staged + digest verified (%llu bytes)", (unsigned long long)size);
	return 0;
}

int plat_commit_and_reboot(uint64_t counter)
{
	/* Record the counter as pending BEFORE the swap, so the freshly-booted image
	 * can promote it once it confirms healthy (and a revert leaves it stale, to
	 * be cleared - never promoted). */
	if (plat_store_pending(counter) != 0) {
		LOG_ERR("could not persist pending counter");
		return -1;
	}
	/* TEST (revertable) swap: if the new image never confirms, MCUboot reverts to
	 * the prior image on the next reboot. */
	if (boot_request_upgrade(BOOT_UPGRADE_TEST) != 0) {
		LOG_ERR("boot_request_upgrade failed");
		return -1;
	}
	LOG_INF("swap requested; rebooting into the new image");
	sys_reboot(SYS_REBOOT_COLD); /* does not return */
	return -1;
}
