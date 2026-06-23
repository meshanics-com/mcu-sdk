/*
 * plat.h - the platform seam between the proven verification core and the
 * device-specific plumbing. These are implemented against Zephyr on
 * the ESP32-S3 (plat_counter.c, plat_net.c, plat_mcuboot.c). Keeping them behind
 * plain declarations keeps main.c and the verifier free of platform headers and
 * documents exactly what the device must do.
 */
#ifndef MESHANICS_PLAT_H
#define MESHANICS_PLAT_H

#include <stddef.h>
#include <stdint.h>

#include "provisioning.h"
#include "identity.h"

/* Bring up WiFi + DHCP using the provisioning config. Returns 0 on success.
 * Identity-bearing TLS credentials are registered separately by
 * plat_net_set_identity once the device has enrolled (or loaded its identity),
 * because on a factory-fresh first boot there are no device credentials yet -
 * they are the OUTPUT of enrollment, which itself needs the network this brings
 * up. The boot-confirm of the running MCUboot image is driven separately by
 * main() via the primitives below (reaching the control plane is the health
 * signal). */
int plat_net_wifi_up(const struct meshanics_provisioning *prov);

/* Register the enrolled identity for the operational mutual-TLS hops (device
 * register/heartbeat, signed-manifest pull, firmware download) and retain the
 * provisioning config those hops address. Returns 0 on success. Call after WiFi
 * is up and a complete identity is in hand. */
int plat_net_set_identity(const struct meshanics_provisioning *prov,
			  const meshanics_identity *id);

/* MCUboot boot-confirm primitives. */
int plat_image_confirmed(void); /* 1 = running image already confirmed, 0 = test image */
int plat_confirm_image(void);   /* boot_write_img_confirmed(); 0 on success */
void plat_reboot(void);         /* cold reboot - used to trigger a revert of a bad image */

/* Pending anti-rollback counter: the counter of an image staged + swapped but not
 * yet confirmed. Promoted to applied on a healthy boot, cleared as stale on a
 * revert. Persisted in NVS beside the applied counter. */
uint64_t plat_pending_counter(void);
int plat_store_pending(uint64_t counter);
int plat_clear_pending(void);

/* POST /device/register so the device appears in the fleet console (identity is
 * taken from the client cert). Returns 0 on success, <0 on error. */
int plat_register(void);

/* POST /device/heartbeat so last_seen advances and the device stays online, and
 * report status for rollouts: the running firmware version,
 * the applied anti-rollback counter, and the agent's self-probe result (the
 * control plane uses these to advance/halt MCU rollout waves). Returns 1 = ok,
 * 0 = control plane reports it decommissioned (stop), <0 on a transient error.
 *
 * If the heartbeat response carries a pending log request, its id is written to
 * log_req_id (NUL-terminated, empty if none); the caller fulfils it with
 * plat_net_upload_logs. Pass NULL/0 to ignore log requests. */
int plat_heartbeat(const char *applied_version, uint64_t applied_counter,
		   int probe_healthy, const char *probe_detail,
		   char *log_req_id, size_t log_req_id_cap);

/* POST a captured log bundle to /device/logs/{request_id} (mutual TLS) to fulfil
 * an operator's log request. body/len is the plain-text log snapshot. Returns 0
 * on success (HTTP 204/200), <0 on a transport/HTTP error. */
int plat_net_upload_logs(const char *request_id, const char *body, size_t len);

/* GET the control plane /device/manifest over mutually-authenticated TLS for this
 * device's stream. Writes the raw SignedManifest bytes into buf. Returns the
 * length, 0 for "nothing assigned" (HTTP 204), or <0 on a transient error. */
int plat_fetch_manifest(uint8_t *buf, size_t cap);

/* Stream the image into the MCUboot secondary slot, checking it hashes to
 * sha256_hex (64 hex chars) and is `size` bytes. Returns 0 on success. */
int plat_stage_image(const char *sha256_hex, uint64_t size);

/* Record `counter` as pending, mark the staged image for a permanent swap, and
 * reboot. Does not return on success. */
int plat_commit_and_reboot(uint64_t counter);

/* The last anti-rollback counter the device successfully applied (0 if none).
 * Persisted in NVS so it survives reboots and power loss - the freshness
 * authority that defeats replayed/older manifests. */
uint64_t plat_applied_counter(void);

/* Persist `counter` as the applied anti-rollback counter. Returns 0 on success.
 * Called when a freshly-booted image confirms healthy. */
int plat_store_counter(uint64_t counter);

/* Failed-target record: the counter of a target that was swapped in and then
 * reverted by MCUboot (never booted healthy). The agent skips re-installing this
 * exact counter so a bad manifest target degrades to idle, not a reboot loop;
 * cleared once a newer image boots healthy. 0 = none. */
uint64_t plat_failed_counter(void);
int plat_store_failed(uint64_t counter);
int plat_clear_failed(void);

#endif /* MESHANICS_PLAT_H */
