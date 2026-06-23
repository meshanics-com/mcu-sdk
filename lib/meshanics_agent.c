/*
 * meshanics_agent.c - the public API + the agent thread that drives the whole
 * lifecycle: connect -> (first boot? enroll : load identity) -> boot-confirm ->
 * register -> online poll/update loop. Connectivity, manifest verification, and
 * the OTA install are handled by the platform, verifier, and OTA components in
 * this directory. There is no insecure path, here or anywhere.
 *
 * The verification core (md_verify, md_check_rollback) is the SAME code proven
 * against the Go reference by the host conformance test. The on-device flow
 * below (enrollment, boot-confirm state machine, polling/install) is lifted from
 * the agent proven on metal, generalised to a provisioned identity (nothing is
 * baked in: the device cert/key and the pinned manifest key are established at
 * first-boot enrollment and read from NVS).
 */
#include <meshanics/agent.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>
#include <zephyr/drivers/hwinfo.h>

#include <psa/crypto.h>
#include <stdio.h>
#include <string.h>

#include "manifest_verify.h"
#include "ota.h"
#include "plat.h"
#include "provisioning.h"
#include "identity.h"
#include "enroll.h"

LOG_MODULE_REGISTER(meshanics_agent, LOG_LEVEL_INF);

/* The control plane is polled (heartbeat + manifest) every POLL_TICKS ticks; the
 * HTTP status server is serviced every tick so the page stays responsive. */
#define TICK K_SECONDS(1)
#define POLL_TICKS CONFIG_MESHANICS_POLL_INTERVAL_SEC
#define HTTP_PORT 80

/* Bounds the received SignedManifest. The real one is ~150 bytes. */
#define MANIFEST_BUF 1024

static struct {
	meshanics_config cfg;
	const char *version;
	volatile meshanics_state state;
	bool started;
	meshanics_identity ident;   /* the enrolled identity (cert/key + pinned key) */
	md_pinned_key pinned;       /* points into ident: pub + key_id */
	uint32_t requests_served;
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

/* --- OTA poll: fetch the desired manifest, verify it, install on a new target -- */
static void poll_once(void)
{
	static uint8_t buf[MANIFEST_BUF];

	int n = plat_fetch_manifest(buf, sizeof(buf));
	if (n <= 0) {
		return; /* 0 = nothing assigned; <0 = transient, retry next tick */
	}

	md_manifest m;
	md_result r = md_verify(&self.pinned, buf, (size_t)n, &m);
	if (r != MD_OK) {
		LOG_WRN("manifest rejected: %s", md_result_str(r));
		return;
	}

	if (!md_check_rollback(plat_applied_counter(), m.rollback_counter)) {
		return; /* already current, or a replayed older manifest */
	}

	/* Skip a target we already staged and that MCUboot then reverted - re-trying
	 * the same bad counter would just reboot-loop. */
	if (m.rollback_counter == plat_failed_counter()) {
		LOG_WRN("skipping target counter %llu: a prior attempt reverted",
			(unsigned long long)m.rollback_counter);
		return;
	}

	/* m.sha256 points into buf and is not NUL-terminated; copy it out. */
	char sha[65];
	memcpy(sha, m.sha256, 64);
	sha[64] = '\0';

	LOG_INF("new target: counter %llu, %llu bytes",
		(unsigned long long)m.rollback_counter, (unsigned long long)m.size_bytes);

	set_state(MESHANICS_STATE_UPDATING);
	if (plat_stage_image(sha, m.size_bytes) != 0) {
		LOG_ERR("image staging failed");
		set_state(MESHANICS_STATE_ONLINE);
		return;
	}
	plat_commit_and_reboot(m.rollback_counter); /* does not return on success */
	LOG_ERR("commit/reboot failed");
	set_state(MESHANICS_STATE_ONLINE);
}

/* boot_confirm runs the anti-rollback boot state machine. The health signal for a
 * freshly-swapped image is "it has network + a registered identity" (net_ok):
 * only such an image is confirmed (so MCUboot keeps it) and gets its counter
 * promoted. A new image that cannot get online is left unconfirmed and rebooted,
 * so MCUboot reverts to the last good image. A transient outage on an already-
 * confirmed image just retries - it is never reverted. */
static void boot_confirm(int net_ok)
{
	int confirmed = plat_image_confirmed();
	if (net_ok) {
		struct ota_boot_action act = ota_plan_boot(confirmed == 1,
			plat_applied_counter(), plat_pending_counter());
		if (act.confirm && plat_confirm_image() == 0) {
			LOG_INF("running image confirmed healthy");
		}
		if (act.promote) {
			plat_store_counter(act.new_applied);
			LOG_INF("anti-rollback counter promoted to %llu",
				(unsigned long long)act.new_applied);
		}
		if (act.clear_pending) {
			plat_clear_pending();
		}
		if (act.record_failed) {
			plat_store_failed(act.failed_counter);
			LOG_WRN("target counter %llu reverted; will not re-attempt it",
				(unsigned long long)act.failed_counter);
		}
		if (act.clear_failed) {
			plat_clear_failed();
		}
		return;
	}
	if (confirmed == 0) {
		LOG_ERR("new image cannot reach control plane; rebooting to revert");
		plat_reboot(); /* does not return */
	}
	LOG_WRN("network down on a confirmed image; will retry, not reverting");
}

/* --- HTTP status server: makes the running firmware version visible ---------- */

static const char *reset_cause_str(void)
{
	uint32_t cause = 0;
	if (hwinfo_get_reset_cause(&cause) != 0) {
		return "unknown";
	}
	if (cause & RESET_POR) {
		return "power-on";
	}
	if (cause & RESET_PIN) {
		return "pin";
	}
	if (cause & RESET_SOFTWARE) {
		return "software";
	}
	if (cause & RESET_WATCHDOG) {
		return "watchdog";
	}
	if (cause & RESET_BROWNOUT) {
		return "brownout";
	}
	return cause ? "other" : "none";
}

static void device_id_hex(char *out, size_t cap)
{
	uint8_t id[16];
	ssize_t n = hwinfo_get_device_id(id, sizeof(id));
	size_t w = 0;
	out[0] = '\0';
	for (ssize_t i = 0; i < n && w + 3 <= cap; i++) {
		w += (size_t)snprintf(out + w, cap - w, "%02x", id[i]);
	}
}

static int build_status(char *out, size_t cap, const char *ip)
{
	char idhex[40];
	device_id_hex(idhex, sizeof(idhex));
	return snprintf(out, cap,
		"{"
		"\"service\":\"meshanics-mcu-agent\","
		"\"version\":\"%s\","
		"\"board\":\"" CONFIG_BOARD "\","
		"\"uptime_seconds\":%lld,"
		"\"applied_counter\":%llu,"
		"\"reset_cause\":\"%s\","
		"\"device_id\":\"%s\","
		"\"ip\":\"%s\","
		"\"key_id\":\"%s\","
		"\"requests_served\":%u"
		"}\n",
		self.version,
		(long long)(k_uptime_get() / 1000),
		(unsigned long long)plat_applied_counter(), reset_cause_str(), idhex, ip,
		self.pinned.key_id, self.requests_served);
}

static int http_listen(void)
{
	int fd = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		return -1;
	}
	int one = 1;
	(void)zsock_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(HTTP_PORT);
	if (zsock_bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
	    zsock_listen(fd, 2) < 0) {
		zsock_close(fd);
		return -1;
	}
	return fd;
}

/* http_serve_pending answers every connection waiting on the listener right now,
 * then returns - it never blocks the agent's heartbeat/poll cadence. */
static void http_serve_pending(int listener)
{
	struct zsock_pollfd pfd = { .fd = listener, .events = ZSOCK_POLLIN };
	while (zsock_poll(&pfd, 1, 0) > 0 && (pfd.revents & ZSOCK_POLLIN)) {
		pfd.revents = 0;
		int c = zsock_accept(listener, NULL, NULL);
		if (c < 0) {
			break;
		}
		char ip[INET_ADDRSTRLEN] = "0.0.0.0";
		struct sockaddr_in local;
		socklen_t llen = sizeof(local);
		if (zsock_getsockname(c, (struct sockaddr *)&local, &llen) == 0) {
			zsock_inet_ntop(AF_INET, &local.sin_addr, ip, sizeof(ip));
		}
		char req[256];
		(void)zsock_recv(c, req, sizeof(req), 0); /* drain the request */
		self.requests_served++;
		char body[512];
		int blen = build_status(body, sizeof(body), ip);
		if (blen > 0 && blen < (int)sizeof(body)) {
			char resp[768];
			int rl = snprintf(resp, sizeof(resp),
				"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
				"Content-Length: %d\r\nConnection: close\r\n\r\n%s", blen, body);
			if (rl > 0 && rl < (int)sizeof(resp)) {
				(void)zsock_send(c, resp, (size_t)rl, 0);
			}
		}
		zsock_close(c);
	}
}

/* establish_identity enrolls on first boot, or loads the stored identity on
 * subsequent boots, and wires the pinned manifest key. Returns 0 on success. */
static int establish_identity(const struct meshanics_provisioning *prov)
{
	if (!meshanics_identity_exists()) {
		set_state(MESHANICS_STATE_ENROLLING);
		LOG_INF("first boot: self-enrolling with the control plane");
		if (meshanics_enroll(prov, &self.ident) != 0) {
			LOG_ERR("enrollment failed");
			return -1;
		}
		if (meshanics_identity_save(&self.ident) != 0) {
			LOG_ERR("could not persist identity; will retry enrollment next boot");
			return -1;
		}
		LOG_INF("enrolled and identity persisted");
	} else if (meshanics_identity_load(&self.ident) != 0) {
		LOG_ERR("stored identity is unreadable");
		return -1;
	}
	self.pinned.pub = self.ident.manifest_pub;
	self.pinned.key_id = self.ident.key_id;
	return 0;
}

static void agent_main(void *a, void *b, void *c)
{
	ARG_UNUSED(a); ARG_UNUSED(b); ARG_UNUSED(c);

	set_state(MESHANICS_STATE_BOOT);
	if (psa_crypto_init() != PSA_SUCCESS) {
		LOG_ERR("psa_crypto_init failed");
		set_state(MESHANICS_STATE_OFFLINE);
		return;
	}

	const struct meshanics_provisioning *prov = meshanics_provisioning_get();
	if (!prov) {
		LOG_ERR("device is not provisioned (no trust anchor); halting agent");
		set_state(MESHANICS_STATE_OFFLINE);
		return;
	}

	set_state(MESHANICS_STATE_CONNECTING);
	if (plat_net_wifi_up(prov) != 0) {
		LOG_ERR("no network; a freshly-swapped image will revert");
		boot_confirm(0); /* reboots to revert if this image is unconfirmed */
		set_state(MESHANICS_STATE_OFFLINE);
		return;
	}

	if (establish_identity(prov) != 0) {
		set_state(MESHANICS_STATE_OFFLINE);
		return;
	}

	if (plat_net_set_identity(prov, &self.ident) != 0) {
		LOG_ERR("could not register identity credentials");
		set_state(MESHANICS_STATE_OFFLINE);
		return;
	}

	/* Net + identity are ready: confirm/promote the running image (or let a bad
	 * one have been reverted), then come online. */
	boot_confirm(1);

	if (plat_register() == 0) {
		LOG_INF("registered with control plane - online in console");
	}
	int http = http_listen();
	LOG_INF("meshanics mcu agent v%s up; status on http://<ip>:%d/ ; key_id %s",
		self.version, HTTP_PORT, self.pinned.key_id);
	set_state(MESHANICS_STATE_ONLINE);

	for (int tick = 0;; tick++) {
		if (http >= 0) {
			http_serve_pending(http);
		}
		if (tick % POLL_TICKS == 0) {
			/* Self-probe: the zero-config default is the agent's own HTTP status
			 * server being up. Reported on the heartbeat so the control plane can
			 * advance/halt this device's rollout wave. An app-specific health()
			 * callback (if set) can veto. */
			int healthy = (http >= 0);
			if (healthy && self.cfg.health && !self.cfg.health(self.cfg.user)) {
				healthy = 0;
			}
			const char *detail = healthy ? "status-server up" : "health check failed";
			int hb = plat_heartbeat(self.version, plat_applied_counter(), healthy, detail);
			if (hb == 0) {
				LOG_WRN("control plane reports decommissioned - stopping");
				break;
			}
			poll_once(); /* OTA check; does not return if it swaps + reboots */
		}
		k_sleep(TICK);
	}
	set_state(MESHANICS_STATE_OFFLINE);
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
	/* Recorded for local diagnostics; fleet metric shipping piggybacks a future
	 * heartbeat field (the heartbeat today carries version + counter + probe). */
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
