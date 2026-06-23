/*
 * plat_store.c - the single NVS mount over the board's `storage` partition.
 * See plat_store.h. Lifts the proven mount sequence from the agent's counter
 * store and generalises it to arbitrary small records, so the counter and the
 * enrolled identity share one file system instead of two colliding ones.
 */
#include "plat_store.h"

#include <zephyr/device.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/fs/nvs.h>
#include <zephyr/storage/flash_map.h>

#define STORE_PARTITION storage_partition

static struct nvs_fs store_fs;
static bool store_ready;

static int store_mount(void)
{
	if (store_ready) {
		return 0;
	}
	store_fs.flash_device = FIXED_PARTITION_DEVICE(STORE_PARTITION);
	if (!device_is_ready(store_fs.flash_device)) {
		return -1;
	}
	store_fs.offset = FIXED_PARTITION_OFFSET(STORE_PARTITION);

	struct flash_pages_info info;
	if (flash_get_page_info_by_offs(store_fs.flash_device, store_fs.offset, &info) != 0) {
		return -1;
	}
	store_fs.sector_size = info.size;
	/* Use the whole partition: the identity records (a ~1 KB device certificate
	 * and key) need more room than the three counters alone, so claim every
	 * sector the partition provides rather than the counter's old fixed three. */
	size_t sectors = FIXED_PARTITION_SIZE(STORE_PARTITION) / info.size;
	store_fs.sector_count = (uint16_t)(sectors < 2 ? 2 : sectors);

	if (nvs_mount(&store_fs) != 0) {
		return -1;
	}
	store_ready = true;
	return 0;
}

int plat_store_read(uint16_t id, void *buf, size_t len)
{
	if (store_mount() != 0) {
		return -1;
	}
	ssize_t n = nvs_read(&store_fs, id, buf, len);
	return (n < 0) ? -1 : (int)n;
}

int plat_store_write(uint16_t id, const void *buf, size_t len)
{
	if (store_mount() != 0) {
		return -1;
	}
	ssize_t n = nvs_write(&store_fs, id, buf, len);
	/* nvs_write returns the bytes written, or 0 when the value is unchanged. */
	return (n == (ssize_t)len || n == 0) ? 0 : -1;
}

int plat_store_delete(uint16_t id)
{
	if (store_mount() != 0) {
		return -1;
	}
	return nvs_delete(&store_fs, id) == 0 ? 0 : -1;
}

int plat_store_exists(uint16_t id)
{
	if (store_mount() != 0) {
		return 0;
	}
	uint8_t probe;
	/* A 1-byte read returns the record's true size if present, -ENOENT if not. */
	return nvs_read(&store_fs, id, &probe, sizeof(probe)) >= 0 ? 1 : 0;
}
