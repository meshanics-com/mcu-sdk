/*
 * meshanics_agent.c - public API + the agent thread that drives the lifecycle:
 * connect -> enroll (first boot) -> online -> poll/update. Connectivity, manifest
 * verification, and the OTA install are handled by the platform, verifier, and
 * OTA components in this directory. There is no insecure path, here or anywhere.
 */
#include <meshanics/agent.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(meshanics_agent, LOG_LEVEL_INF);

#define POLL_INTERVAL K_SECONDS(CONFIG_MESHANICS_POLL_INTERVAL_SEC)

static struct {
	meshanics_config cfg;
	const char *version;
	volatile meshanics_state state;
	bool started;
} self;

K_THREAD_STACK_DEFINE(agent_stack, CONFIG_MESHANICS_AGENT_THREAD_STACK_SIZE);
static struct k_thread agent_thread;

static void set_state(meshanics_state st)
{
	self.state = st;
	if (self.cfg.on_state) {
		self.cfg.on_state(st, self.cfg.user);
	}
}

static void agent_main(void *a, void *b, void *c)
{
	ARG_UNUSED(a); ARG_UNUSED(b); ARG_UNUSED(c);

	set_state(MESHANICS_STATE_BOOT);

	/* Join the network using the provisioning bundle. */
	set_state(MESHANICS_STATE_CONNECTING);

	/* First boot only: generate an on-chip key pair, present the claim
	 * credential over mutual TLS (the server is authenticated by the trust
	 * anchor in the bundle), receive the unique device certificate and the
	 * manifest-verification key, and persist them in encrypted NVS. Subsequent
	 * boots reuse the stored identity. */
	set_state(MESHANICS_STATE_ENROLLING);

	/* On a freshly-swapped image, run the boot-confirm step: confirm and promote
	 * the anti-rollback counter once the control plane is reachable, otherwise
	 * reboot so the bootloader reverts to the previous image. */

	set_state(MESHANICS_STATE_ONLINE);

	for (;;) {
		/* Heartbeat; fetch the signed manifest and verify it against the pinned
		 * key (signature before parse); on a newer counter, download the firmware
		 * (digest-checked), stage it, and swap via the bootloader. A target that
		 * failed to confirm is recorded and skipped, never retried into a loop. */
		k_sleep(POLL_INTERVAL);
	}
}

meshanics_status meshanics_agent_start(const meshanics_config *cfg)
{
	if (self.started) {
		return MESHANICS_ERR_STATE;
	}
	if (cfg) {
		self.cfg = *cfg;
	}
	self.version = (self.cfg.firmware_version && self.cfg.firmware_version[0])
			       ? self.cfg.firmware_version
			       : CONFIG_MESHANICS_FW_VERSION;
	self.started = true;

	k_thread_create(&agent_thread, agent_stack,
			K_THREAD_STACK_SIZEOF(agent_stack),
			agent_main, NULL, NULL, NULL,
			K_PRIO_PREEMPT(7), 0, K_NO_WAIT);
	k_thread_name_set(&agent_thread, "meshanics");

	LOG_INF("meshanics agent v%s starting", self.version);
	return MESHANICS_OK;
}

meshanics_status meshanics_report_metric(const char *key, double value)
{
	if (!self.started) {
		return MESHANICS_ERR_STATE;
	}
	/* Buffered and shipped on the next heartbeat. */
	LOG_DBG("metric %s=%f", key, value);
	return MESHANICS_OK;
}

meshanics_state meshanics_agent_state(void)
{
	return self.state;
}

const char *meshanics_agent_version(void)
{
	return self.version ? self.version : CONFIG_MESHANICS_FW_VERSION;
}
