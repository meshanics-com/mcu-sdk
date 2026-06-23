/*
 * meshanics/agent.h - public API for the Meshanics MCU agent SDK.
 *
 * Link this library into your Zephyr firmware and call meshanics_agent_start()
 * once from main(). The agent runs in its own thread and owns: WiFi/connectivity,
 * first-boot enrollment, signed-manifest polling, OTA download, MCUboot A/B swap,
 * anti-rollback, boot-confirm/auto-revert, heartbeat, and metric reporting.
 *
 * Trust model (profile A, ADR-0029): the device verifies a compact update
 * manifest against the tenant's Ed25519 public key (provisioned at enrollment),
 * and MCUboot verifies the image signature (your key) at boot. The update payload
 * is end-to-end signed independent of transport. There is no insecure path.
 */
#ifndef MESHANICS_AGENT_H
#define MESHANICS_AGENT_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Result codes returned by the API. */
typedef enum {
	MESHANICS_OK = 0,
	MESHANICS_ERR_CONFIG = -1,   /* missing/invalid provisioning config */
	MESHANICS_ERR_NETWORK = -2,  /* could not reach the control plane */
	MESHANICS_ERR_ENROLL = -3,   /* enrollment/claim rejected */
	MESHANICS_ERR_STATE = -4,    /* called in the wrong state (e.g. twice) */
	MESHANICS_ERR_NOMEM = -5,
} meshanics_status;

/** Lifecycle states reported to an optional callback. */
typedef enum {
	MESHANICS_STATE_BOOT,        /* agent thread started */
	MESHANICS_STATE_CONNECTING,  /* joining the network */
	MESHANICS_STATE_ENROLLING,   /* first-boot claim/enrollment */
	MESHANICS_STATE_ONLINE,      /* registered + heartbeating */
	MESHANICS_STATE_UPDATING,    /* downloading/staging an update */
	MESHANICS_STATE_OFFLINE,     /* lost connectivity; retrying */
} meshanics_state;

/**
 * Optional health check, invoked once after a freshly-swapped image boots. Return
 * false to reject the new image (MCUboot reverts to the previous one). If you do
 * not set one, the default health signal is "the agent reached the control plane".
 * Keep it fast and side-effect-free.
 */
typedef bool (*meshanics_health_fn)(void *user);

/** Optional configuration. Pass NULL to use Kconfig + provisioned defaults. */
typedef struct {
	/* Firmware version reported to the fleet and matched against rollout targets.
	 * NULL => CONFIG_MESHANICS_FW_VERSION. */
	const char *firmware_version;

	/* Optional lifecycle callback (may be NULL). */
	void (*on_state)(meshanics_state state, void *user);

	/* Optional post-update health check (may be NULL). */
	meshanics_health_fn health;

	/* Passed back to on_state/health. */
	void *user;
} meshanics_config;

/**
 * Start the agent. Spawns the agent thread and returns once it is running; it
 * does NOT block your application loop. Call exactly once.
 *
 * @param cfg optional overrides, or NULL for defaults.
 * @return MESHANICS_OK on success, or a negative meshanics_status.
 */
meshanics_status meshanics_agent_start(const meshanics_config *cfg);

/**
 * Report a named numeric metric to the fleet. Metrics feed rollout health/halt
 * rules and dashboards. Cheap and non-blocking (buffered, shipped on the next
 * heartbeat). Safe to call from your application thread.
 */
meshanics_status meshanics_report_metric(const char *key, double value);

/** Current lifecycle state (for your own UI/LED). */
meshanics_state meshanics_agent_state(void);

/** Running firmware version string (the value reported to the fleet). */
const char *meshanics_agent_version(void);

#ifdef __cplusplus
}
#endif

#endif /* MESHANICS_AGENT_H */
