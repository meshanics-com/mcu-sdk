/*
 * ota - pure, host-tested logic for the firmware installer. It holds the two
 * pieces most likely to hide a bug:
 *   1. parsing/planning the chunked firmware download (HTTP Range), and
 *   2. the boot-confirm anti-rollback state machine - deciding, on each boot,
 *      whether the running image is a freshly-swapped one to confirm and promote,
 *      or a reverted-to old image whose pending counter is now stale.
 *
 * No Zephyr/network/flash dependency, so it is host-testable. The device flash +
 * MCUboot calls that act on these decisions are verified separately.
 */
#ifndef MESHANICS_MCU_OTA_H
#define MESHANICS_MCU_OTA_H

#include <stddef.h>
#include <stdint.h>

/* ota_parse_content_range parses an HTTP "Content-Range" value of the form
 * "bytes <start>-<end>/<total>" (the form http.ServeContent emits). On success it
 * fills start/end/total and returns 1; on any malformed input it returns 0 and
 * leaves the outputs untouched. value points at the bytes AFTER "Content-Range:"
 * (leading spaces tolerated); it need not be NUL-terminated within len. */
int ota_parse_content_range(const char *value, size_t len, uint64_t *start,
			    uint64_t *end, uint64_t *total);

/* ota_chunk_len returns how many bytes to request next, given the bytes already
 * written (offset), the total image size, and the largest chunk the device will
 * buffer. Returns 0 when the download is complete (offset >= total). */
uint64_t ota_chunk_len(uint64_t offset, uint64_t total, uint32_t max_chunk);

/* ota_boot_action is the plan for a boot, computed from the MCUboot
 * image-confirmed flag and the two persisted counters. The device executes it:
 * confirm the running image (so it is not reverted), promote the applied
 * anti-rollback counter, and/or erase the now-stale pending record. */
struct ota_boot_action {
	int confirm;          /* call boot_write_img_confirmed() */
	int promote;          /* persist applied = new_applied */
	uint64_t new_applied; /* the counter to persist when promote != 0 */
	int clear_pending;    /* erase the pending counter record */
	int record_failed;    /* persist failed = failed_counter (a target that reverted) */
	uint64_t failed_counter;
	int clear_failed;     /* erase the failed record (a newer image booted healthy) */
};

/* ota_plan_boot decides what to do on a boot:
 *  - running image not yet confirmed: confirm it so it sticks; if a pending
 *    counter newer than applied is recorded, this is the freshly-swapped image -
 *    promote it and clear the failed record (a good image booted); clear any
 *    pending record either way.
 *  - running image already confirmed: a pending record means the swap reverted
 *    (we booted the old, confirmed image) or it is leftover - clear it as stale,
 *    never promote, and record that counter as failed so the agent does not
 *    re-attempt the same bad target in a reboot loop.
 * applied is the last confirmed anti-rollback counter; pending is the counter a
 * commit staged for the image just swapped in (0 = none). */
struct ota_boot_action ota_plan_boot(int img_confirmed, uint64_t applied, uint64_t pending);

/* ota_heartbeat_json builds the device heartbeat request body: the agent
 * version, the firmware version the device is running, the applied anti-rollback
 * counter, the agent's self-probe result, and - if the device just had a target
 * reverted by MCUboot - the reverted_version, so the control plane can mark this
 * device's rollout assignment reverted. Writes a NUL-terminated JSON object into
 * out and returns its length, or -1 if it does not fit. detail and
 * reverted_version are bounded and sanitised (quotes, backslashes and control
 * chars become spaces) so a stray value cannot break the JSON. Pass NULL/"" for
 * reverted_version to omit it. */
int ota_heartbeat_json(char *out, size_t cap, const char *agent_version,
		       const char *applied_version, uint64_t applied_counter,
		       int healthy, const char *detail, const char *reverted_version);

#endif /* MESHANICS_MCU_OTA_H */
