/*
 * meshanics_agent.c - public API + agent thread skeleton.
 *
 * SCAFFOLD: this drives the lifecycle and exposes the public API. The network /
 * enrollment / verify / OTA work is performed by the platform + verify + ota
 * modules being vendored from the Meshanics monorepo (see lib/README.md). The
 * call sites are marked `EXTRACT:`. This is deliberately honest scaffolding -
 * it does not fake OTA; until the modules are wired the agent reports its state
 * and idles. There is no insecure path here or anywhere else.
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

	/* EXTRACT(plat_net): join the network using the provisioning bundle. */
	set_state(MESHANICS_STATE_CONNECTING);

	/* EXTRACT(enroll): first boot only - generate an on-chip key pair, present
	 * the claim credential over mutual TLS (server authenticated by the baked
	 * CA), receive the unique device cert + the tenant manifest public key, and
	 * persist them in encrypted NVS. Subsequent boots reuse the NVS identity. */
	set_state(MESHANICS_STATE_ENROLLING);

	/* EXTRACT(ota): on a fresh image, run the boot-confirm state machine -
	 * confirm + promote the anti-rollback counter once we reach the control
	 * plane, else reboot so MCUboot reverts. */

	set_state(MESHANICS_STATE_ONLINE);

	for (;;) {
		/* EXTRACT(plat_net + verify + ota): heartbeat; fetch the signed manifest;
		 * md_verify against the provisioned key (verify before parse); if a newer
		 * counter, set UPDATING, stream the firmware (digest-checked), MCUboot
		 * swap + reboot. A failed target is recorded and skipped, not retried. */
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
	/* EXTRACT(metrics): buffer and ship on the next heartbeat. */
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
