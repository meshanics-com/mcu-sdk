/*
 * plat_net.c - WiFi + mutually-authenticated TLS networking for the ESP32-S3
 * agent. Implements the network half of the platform seam: bring up WiFi
 * (plat_net_wifi_up), register the enrolled identity (plat_net_set_identity),
 * pull the signed manifest (plat_fetch_manifest), stream the firmware image for
 * the installer (plat_net_firmware_download), and report register/heartbeat.
 *
 * The TLS setup (TLS 1.3, EC P-256 client+server auth, PEM-parsed creds) is the
 * configuration proven on metal; this file lifts that path. Unlike the original
 * bench code it bakes nothing in: the control-plane hosts/ports come from the
 * provisioning config and the credentials from the NVS-stored identity, both
 * passed in at runtime.
 */
#include "plat.h"
#include "plat_net.h"
#include "ota.h"

#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/dhcpv4.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/logging/log.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

LOG_MODULE_REGISTER(plat_net, LOG_LEVEL_INF);

#define SEC_TAG 0x10

/* The SDK agent build version, reported in register/heartbeat as agent_version
 * (distinct from the firmware version the device runs, which the rollout matches
 * and which the agent passes in to plat_heartbeat). */
#define SDK_AGENT_VERSION "meshanics-mcu-0.1.0"

/* Provisioning config the operational hops address; set by the init calls. */
static const struct meshanics_provisioning *cfg;

static volatile int wifi_connected;
static struct net_mgmt_event_callback wifi_cb;

static void wifi_evt(struct net_mgmt_event_callback *cb, uint64_t ev, struct net_if *iface)
{
	ARG_UNUSED(iface);
	if (ev == NET_EVENT_WIFI_CONNECT_RESULT) {
		const struct wifi_status *st = cb->info;

		if (st->status) {
			LOG_WRN("WiFi connect failed (%d)", st->status);
		} else {
			LOG_INF("WiFi connected");
			wifi_connected = 1;
		}
	}
}

int plat_net_wifi_up(const struct meshanics_provisioning *prov)
{
	if (!prov) {
		return -1;
	}
	cfg = prov;

	net_mgmt_init_event_callback(&wifi_cb, wifi_evt, NET_EVENT_WIFI_CONNECT_RESULT);
	net_mgmt_add_event_callback(&wifi_cb);

	struct net_if *iface = net_if_get_default();
	struct wifi_connect_req_params p = {
		.ssid = (const uint8_t *)prov->wifi_ssid,
		.ssid_length = strlen(prov->wifi_ssid),
		.psk = (const uint8_t *)prov->wifi_psk,
		.psk_length = strlen(prov->wifi_psk),
		.security = WIFI_SECURITY_TYPE_PSK,
		.channel = WIFI_CHANNEL_ANY,
	};
	for (int t = 0; t < 10 && net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &p, sizeof(p)) != 0; t++) {
		k_msleep(500);
	}
	for (int t = 0; t < 200 && !wifi_connected; t++) {
		k_msleep(100);
	}
	if (!wifi_connected) {
		return -1;
	}
	net_dhcpv4_start(iface);
	/* Let the DHCP lease + default route settle before the first connect. */
	k_msleep(3000);
	return 0;
}

int plat_net_set_identity(const struct meshanics_provisioning *prov, const meshanics_identity *id)
{
	if (!prov || !id) {
		return -1;
	}
	cfg = prov;
	int rc = tls_credential_add(SEC_TAG, TLS_CREDENTIAL_CA_CERTIFICATE,
				    prov->server_ca, strlen(prov->server_ca) + 1);
	if (rc) {
		LOG_ERR("register server CA failed (%d)", rc);
		return -1;
	}
	rc = tls_credential_add(SEC_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
				id->device_cert_pem, strlen(id->device_cert_pem) + 1);
	if (rc) {
		LOG_ERR("register device cert failed (%d)", rc);
		return -1;
	}
	rc = tls_credential_add(SEC_TAG, TLS_CREDENTIAL_PRIVATE_KEY,
				id->device_key_pem, strlen(id->device_key_pem) + 1);
	if (rc) {
		LOG_ERR("register device key failed (%d)", rc);
		return -1;
	}
	return 0;
}

/* tls_connect opens a mutually-authenticated TLS connection to the control plane
 * on the given port and returns the socket fd, or <0. */
static int tls_connect(uint16_t port)
{
	int fd = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	if (fd < 0) {
		return -1;
	}
	sec_tag_t tags[] = { SEC_TAG };
	int verify = TLS_PEER_VERIFY_REQUIRED;
	(void)zsock_setsockopt(fd, SOL_TLS, TLS_SEC_TAG_LIST, tags, sizeof(tags));
	(void)zsock_setsockopt(fd, SOL_TLS, TLS_HOSTNAME, cfg->server_host, strlen(cfg->server_host));
	(void)zsock_setsockopt(fd, SOL_TLS, TLS_PEER_VERIFY, &verify, sizeof(verify));
	/* A stalled connection must error, never hang the agent forever. */
	struct zsock_timeval rcvto = { .tv_sec = 20, .tv_usec = 0 };
	(void)zsock_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcvto, sizeof(rcvto));

	struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	zsock_inet_pton(AF_INET, cfg->server_ip, &addr.sin_addr);
	if (zsock_connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		int e = errno;
		zsock_close(fd);
		LOG_WRN("connect/handshake (port %u) failed errno=%d", port, e);
		return -2;
	}
	return fd;
}

static int http_status(const uint8_t *buf, size_t len)
{
	if (len < 12 || memcmp(buf, "HTTP/1.", 7) != 0) {
		return -1;
	}
	return (buf[9] - '0') * 100 + (buf[10] - '0') * 10 + (buf[11] - '0');
}

/* recv_all reads the whole response (Connection: close) into buf, returns the
 * total length (NUL-terminated within cap), or <0 on a socket error. */
static int recv_all(int fd, uint8_t *buf, size_t cap)
{
	size_t total = 0;
	while (total < cap - 1) {
		int n = zsock_recv(fd, buf + total, cap - 1 - total, 0);
		if (n < 0) {
			return -1;
		}
		if (n == 0) {
			break;
		}
		total += (size_t)n;
	}
	buf[total] = '\0';
	return (int)total;
}

/* body_offset returns the index just past the header-terminating CRLFCRLF, or
 * -1 if not found. */
static int body_offset(const uint8_t *buf, size_t len)
{
	for (size_t i = 0; i + 4 <= len; i++) {
		if (memcmp(buf + i, "\r\n\r\n", 4) == 0) {
			return (int)(i + 4);
		}
	}
	return -1;
}

int plat_fetch_manifest(uint8_t *buf, size_t cap)
{
	int fd = tls_connect(cfg->artifact_port);
	if (fd < 0) {
		return fd;
	}
	char req[256];
	int rl = snprintf(req, sizeof(req),
		"GET /device/manifest?artifact_name=%s&target_profile=%s HTTP/1.1\r\n"
		"Host: %s\r\nConnection: close\r\n\r\n",
		cfg->artifact_name, cfg->target_profile, cfg->server_host);
	if (rl <= 0 || rl >= (int)sizeof(req) || zsock_send(fd, req, (size_t)rl, 0) < 0) {
		zsock_close(fd);
		return -3;
	}
	int total = recv_all(fd, buf, cap);
	zsock_close(fd);
	if (total < 0) {
		return -3;
	}
	int code = http_status(buf, (size_t)total);
	if (code == 204) {
		return 0; /* nothing assigned */
	}
	if (code != 200) {
		return -4;
	}
	int off = body_offset(buf, (size_t)total);
	if (off < 0) {
		return -4;
	}
	size_t blen = (size_t)total - (size_t)off;
	memmove(buf, buf + off, blen);
	return (int)blen;
}

/* post_device opens mTLS to the control plane on `port`, POSTs a JSON body, and
 * returns the HTTP status code (or <0 on a transport error). The response is left
 * NUL-terminated at the front of resp so the caller can scan the body. */
static int post_device(uint16_t port, const char *path, const char *body,
		       uint8_t *resp, size_t cap)
{
	int fd = tls_connect(port);
	if (fd < 0) {
		return fd;
	}
	/* Headers (~130 B) + the JSON body must both fit; 512 leaves headroom. */
	char req[512];
	int rl = snprintf(req, sizeof(req),
		"POST %s HTTP/1.1\r\nHost: %s\r\n"
		"Content-Type: application/json\r\nContent-Length: %u\r\n"
		"Connection: close\r\n\r\n%s",
		path, cfg->server_host, (unsigned)strlen(body), body);
	if (rl <= 0 || rl >= (int)sizeof(req)) {
		zsock_close(fd);
		return -3;
	}
	if (zsock_send(fd, req, (size_t)rl, 0) < 0) {
		zsock_close(fd);
		return -3;
	}
	int total = recv_all(fd, resp, cap);
	zsock_close(fd);
	if (total < 0) {
		return -3;
	}
	return http_status(resp, (size_t)total);
}

int plat_register(void)
{
	char body[160];
	int bl = snprintf(body, sizeof(body),
		"{\"hw_profile\":\"%s\",\"agent_version\":\"%s\"}",
		cfg->target_profile, SDK_AGENT_VERSION);
	if (bl <= 0 || bl >= (int)sizeof(body)) {
		return -3;
	}
	uint8_t resp[512];
	int code = post_device(cfg->fleet_port, "/device/register", body, resp, sizeof(resp));
	if (code < 0) {
		return code;
	}
	return code == 200 ? 0 : -5;
}

int plat_heartbeat(const char *applied_version, uint64_t applied_counter,
		   int probe_healthy, const char *probe_detail)
{
	char body[256];
	if (ota_heartbeat_json(body, sizeof(body), SDK_AGENT_VERSION, applied_version,
			       applied_counter, probe_healthy, probe_detail) < 0) {
		return -3;
	}
	uint8_t resp[512];
	int code = post_device(cfg->fleet_port, "/device/heartbeat", body, resp, sizeof(resp));
	if (code < 0) {
		return code;
	}
	if (code != 200) {
		return -6;
	}
	/* The 200 body carries decommissioned=true on an operator Offboard. */
	if (strstr((char *)resp, "\"decommissioned\":true")) {
		return 0;
	}
	return 1;
}

int plat_net_firmware_download(uint64_t expect_size, plat_fw_sink sink, void *ctx)
{
	int fd = tls_connect(cfg->artifact_port);
	if (fd < 0) {
		return fd;
	}
	char req[256];
	int rl = snprintf(req, sizeof(req),
		"GET /device/firmware?artifact_name=%s&target_profile=%s HTTP/1.1\r\n"
		"Host: %s\r\nConnection: close\r\n\r\n",
		cfg->artifact_name, cfg->target_profile, cfg->server_host);
	if (rl <= 0 || rl >= (int)sizeof(req) || zsock_send(fd, req, (size_t)rl, 0) < 0) {
		zsock_close(fd);
		return -3;
	}

	/* Read past the HTTP headers, then stream the body straight to the sink. */
	uint8_t buf[1536];
	size_t acc = 0;
	int boff = -1;
	while (boff < 0) {
		int n = zsock_recv(fd, buf + acc, sizeof(buf) - acc, 0);
		if (n <= 0) {
			zsock_close(fd);
			return -3;
		}
		acc += (size_t)n;
		boff = body_offset(buf, acc);
		if (boff < 0 && acc == sizeof(buf)) {
			zsock_close(fd); /* headers larger than our buffer */
			return -4;
		}
	}
	int code = http_status(buf, acc);
	if (code != 200 && code != 206) {
		zsock_close(fd);
		return -4;
	}

	uint64_t got = 0;
	int lastn = 0;
	/* Body bytes that arrived alongside the headers. */
	size_t first = acc - (size_t)boff;
	if (first > 0) {
		size_t take = (got + first > expect_size) ? (size_t)(expect_size - got) : first;
		if (sink(buf + boff, take, (got + take >= expect_size), ctx) != 0) {
			zsock_close(fd);
			return -5;
		}
		got += take;
	}
	while (got < expect_size) {
		int n = zsock_recv(fd, buf, sizeof(buf), 0);
		lastn = n;
		if (n <= 0) {
			break;
		}
		size_t take = (got + (size_t)n > expect_size) ? (size_t)(expect_size - got) : (size_t)n;
		if (sink(buf, take, (got + take >= expect_size), ctx) != 0) {
			zsock_close(fd);
			return -5;
		}
		got += take;
	}
	zsock_close(fd);
	if (got != expect_size) {
		LOG_ERR("fw short: got=%llu expect=%llu lastn=%d errno=%d",
			(unsigned long long)got, (unsigned long long)expect_size, lastn, errno);
		return -1;
	}
	return 0;
}
