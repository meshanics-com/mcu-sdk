/*
 * plat_counter.c - NVS-backed anti-rollback counters.
 *
 * The device's last-applied counter must survive reboot and power loss: it is
 * the freshness authority that lets the verifier refuse a replayed or older
 * manifest. The counters live in the board's `storage` flash partition, accessed
 * through the shared plat_store mount (which the enrolled identity also uses, so
 * the two never collide on the same flash region).
 */
#include "plat.h"
#include "plat_store.h"

#include <string.h>

#define COUNTER_NVS_ID 1
/* The counter of an image that has been staged + swapped but not yet confirmed
 * healthy. Promoted to the applied counter on a confirmed boot, or cleared as
 * stale after a revert - never promoted on a revert. */
#define PENDING_NVS_ID 2
/* The counter of a target that was staged, swapped and then reverted by MCUboot
 * (it never booted healthy). Recorded so the agent does not re-attempt the same
 * bad target in a reboot loop; cleared once a newer image boots healthy. */
#define FAILED_NVS_ID 3
/* The firmware version string of the target last staged + swapped (persisted at
 * commit). If that image reverts, this is the version to report as reverted. */
#define ATTEMPTED_VERSION_NVS_ID 4

/* read_counter returns the stored u64 for `id`, or 0 if nothing is stored. */
static uint64_t read_counter(uint16_t id)
{
	uint64_t value = 0;
	int n = plat_store_read(id, &value, sizeof(value));
	return (n == (int)sizeof(value)) ? value : 0;
}

uint64_t plat_applied_counter(void)
{
	return read_counter(COUNTER_NVS_ID);
}

int plat_store_counter(uint64_t counter)
{
	return plat_store_write(COUNTER_NVS_ID, &counter, sizeof(counter));
}

uint64_t plat_pending_counter(void)
{
	return read_counter(PENDING_NVS_ID);
}

int plat_store_pending(uint64_t counter)
{
	return plat_store_write(PENDING_NVS_ID, &counter, sizeof(counter));
}

int plat_clear_pending(void)
{
	return plat_store_delete(PENDING_NVS_ID);
}

uint64_t plat_failed_counter(void)
{
	return read_counter(FAILED_NVS_ID);
}

int plat_store_failed(uint64_t counter)
{
	return plat_store_write(FAILED_NVS_ID, &counter, sizeof(counter));
}

int plat_clear_failed(void)
{
	return plat_store_delete(FAILED_NVS_ID);
}

int plat_store_attempted_version(const char *version)
{
	if (version == NULL) {
		return -1;
	}
	return plat_store_write(ATTEMPTED_VERSION_NVS_ID, version, strlen(version));
}

int plat_attempted_version(char *out, size_t cap)
{
	if (out == NULL || cap == 0) {
		return -1;
	}
	int n = plat_store_read(ATTEMPTED_VERSION_NVS_ID, out, cap - 1);
	if (n <= 0 || n >= (int)cap) {
		return -1;
	}
	out[n] = '\0';
	return 0;
}

int plat_clear_attempted_version(void)
{
	return plat_store_delete(ATTEMPTED_VERSION_NVS_ID);
}
