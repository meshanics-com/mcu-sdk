#include "ota.h"

#include <stdio.h>

/* parse_u64 reads digits from p[0..len) starting at *i, returns the value and
 * advances *i. Sets *ok=0 if there is not at least one digit. */
static uint64_t parse_u64(const char *p, size_t len, size_t *i, int *ok)
{
	uint64_t v = 0;
	size_t start = *i;
	while (*i < len && p[*i] >= '0' && p[*i] <= '9') {
		v = v * 10 + (uint64_t)(p[*i] - '0');
		(*i)++;
	}
	*ok = (*i > start);
	return v;
}

int ota_parse_content_range(const char *value, size_t len, uint64_t *start,
			    uint64_t *end, uint64_t *total)
{
	if (value == NULL) {
		return 0;
	}
	size_t i = 0;
	while (i < len && (value[i] == ' ' || value[i] == '\t')) {
		i++;
	}
	static const char unit[] = "bytes";
	for (size_t k = 0; k < sizeof(unit) - 1; k++, i++) {
		if (i >= len || value[i] != unit[k]) {
			return 0;
		}
	}
	while (i < len && value[i] == ' ') {
		i++;
	}
	int ok = 0;
	uint64_t s = parse_u64(value, len, &i, &ok);
	if (!ok || i >= len || value[i] != '-') {
		return 0;
	}
	i++;
	uint64_t e = parse_u64(value, len, &i, &ok);
	if (!ok || i >= len || value[i] != '/') {
		return 0;
	}
	i++;
	uint64_t t = parse_u64(value, len, &i, &ok);
	if (!ok) {
		return 0;
	}
	/* A coherent range: start <= end < total. */
	if (s > e || e >= t) {
		return 0;
	}
	*start = s;
	*end = e;
	*total = t;
	return 1;
}

uint64_t ota_chunk_len(uint64_t offset, uint64_t total, uint32_t max_chunk)
{
	if (offset >= total || max_chunk == 0) {
		return 0;
	}
	uint64_t remaining = total - offset;
	return remaining < max_chunk ? remaining : max_chunk;
}

struct ota_boot_action ota_plan_boot(int img_confirmed, uint64_t applied, uint64_t pending)
{
	struct ota_boot_action a = {0};
	if (!img_confirmed) {
		/* First boot of a not-yet-confirmed image (a fresh swap, or a USB
		 * flash): confirm it so MCUboot does not revert on the next reboot. */
		a.confirm = 1;
		if (pending > applied) {
			a.promote = 1;
			a.new_applied = pending;
			/* A newer image booted healthy: any earlier bad-target streak is
			 * over, so forget the failed record. */
			a.clear_failed = 1;
		}
		a.clear_pending = (pending != 0);
	} else if (pending != 0) {
		/* We are running an already-confirmed image but a pending counter is
		 * recorded: the swap reverted (the new image never confirmed and
		 * MCUboot fell back), or it is leftover. Either way it is stale - drop
		 * it and keep applied where it is. Never promote. Record the reverted
		 * counter as failed so we do not re-attempt the same bad target and
		 * reboot-loop; a different (newer) counter is still tried. */
		a.clear_pending = 1;
		a.record_failed = 1;
		a.failed_counter = pending;
	}
	return a;
}

/* sanitise copies up to cap-1 bytes of s into out, replacing characters that
 * would break a JSON string (quote, backslash, control chars) with spaces. */
static void sanitise(char *out, size_t cap, const char *s)
{
	size_t i = 0;
	for (; s != NULL && s[i] != '\0' && i < cap - 1; i++) {
		char c = s[i];
		out[i] = (c == '"' || c == '\\' || c < 0x20) ? ' ' : c;
	}
	out[i] = '\0';
}

int ota_heartbeat_json(char *out, size_t cap, const char *agent_version,
		       const char *applied_version, uint64_t applied_counter,
		       int healthy, const char *detail, const char *reverted_version)
{
	if (out == NULL || cap == 0) {
		return -1;
	}
	if (agent_version == NULL) {
		agent_version = "";
	}
	if (applied_version == NULL) {
		applied_version = "";
	}
	char d[64];
	sanitise(d, sizeof(d), detail);

	int n;
	if (reverted_version != NULL && reverted_version[0] != '\0') {
		/* The device swapped this version in and MCUboot reverted it; report it so
		 * the rollout marks this device's assignment reverted. */
		char rv[32];
		sanitise(rv, sizeof(rv), reverted_version);
		n = snprintf(out, cap,
			"{\"agent_version\":\"%s\",\"applied_version\":\"%s\","
			"\"applied_counter\":%llu,\"reverted_version\":\"%s\","
			"\"probe\":{\"healthy\":%s,\"detail\":\"%s\"}}",
			agent_version, applied_version, (unsigned long long)applied_counter,
			rv, healthy ? "true" : "false", d);
	} else {
		n = snprintf(out, cap,
			"{\"agent_version\":\"%s\",\"applied_version\":\"%s\","
			"\"applied_counter\":%llu,\"probe\":{\"healthy\":%s,\"detail\":\"%s\"}}",
			agent_version, applied_version, (unsigned long long)applied_counter,
			healthy ? "true" : "false", d);
	}
	if (n < 0 || (size_t)n >= cap) {
		return -1;
	}
	return n;
}
