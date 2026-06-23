/*
 * applog.c - a Zephyr log backend that mirrors formatted log lines into a fixed
 * circular RAM buffer, so the agent can ship its recent logs to the control plane
 * on request. See applog.h. Runs alongside the normal console backend.
 */
#include "applog.h"

#include <zephyr/kernel.h>
#include <zephyr/logging/log_backend.h>
#include <zephyr/logging/log_output.h>
#include <zephyr/logging/log_core.h>

#include <string.h>

#define RING_SIZE CONFIG_MESHANICS_LOG_BUF_SIZE

static char ring[RING_SIZE];
static size_t ring_head; /* index of the next byte to write */
static size_t ring_len;  /* bytes currently retained (<= RING_SIZE) */
static struct k_spinlock ring_lock;

static void ring_put(const uint8_t *data, size_t len)
{
	k_spinlock_key_t key = k_spin_lock(&ring_lock);
	for (size_t i = 0; i < len; i++) {
		ring[ring_head] = (char)data[i];
		ring_head = (ring_head + 1) % RING_SIZE;
		if (ring_len < RING_SIZE) {
			ring_len++;
		}
	}
	k_spin_unlock(&ring_lock, key);
}

/* log_output formats each message into this scratch buffer, calling out_write
 * with the bytes; we forward them into the ring. */
static uint8_t fmt_buf[64];

static int out_write(uint8_t *data, size_t length, void *ctx)
{
	ARG_UNUSED(ctx);
	ring_put(data, length);
	return (int)length;
}

LOG_OUTPUT_DEFINE(applog_output, out_write, fmt_buf, sizeof(fmt_buf));

static void applog_process(const struct log_backend *const backend,
			   union log_msg_generic *msg)
{
	ARG_UNUSED(backend);
	/* Level + module name + message text; no timestamp (avoids needing a clock
	 * source set up, and the control plane stamps receipt anyway). */
	log_output_msg_process(&applog_output, &msg->log, LOG_OUTPUT_FLAG_LEVEL);
}

static void applog_init(const struct log_backend *const backend)
{
	ARG_UNUSED(backend);
}

static void applog_panic(const struct log_backend *const backend)
{
	ARG_UNUSED(backend);
}

static void applog_dropped(const struct log_backend *const backend, uint32_t cnt)
{
	ARG_UNUSED(backend);
	ARG_UNUSED(cnt);
}

static const struct log_backend_api applog_api = {
	.process = applog_process,
	.init = applog_init,
	.panic = applog_panic,
	.dropped = applog_dropped,
};

LOG_BACKEND_DEFINE(meshanics_applog, applog_api, true);

size_t applog_snapshot(char *out, size_t cap)
{
	if (!out || cap == 0) {
		return 0;
	}
	k_spinlock_key_t key = k_spin_lock(&ring_lock);
	size_t n = ring_len;
	if (n > cap - 1) {
		n = cap - 1; /* keep the newest bytes if the caller's buffer is smaller */
	}
	size_t start = (ring_head + RING_SIZE - n) % RING_SIZE;
	for (size_t i = 0; i < n; i++) {
		out[i] = ring[(start + i) % RING_SIZE];
	}
	out[n] = '\0';
	k_spin_unlock(&ring_lock, key);
	return n;
}
