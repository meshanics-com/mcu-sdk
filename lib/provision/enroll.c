/*
 * enroll.c - on-device first-boot enrollment. See enroll.h.
 *
 * This lifts the path proven on metal by the claim-test bench app: an on-chip EC
 * P-256 key + CSR (generated through PSA, because this Zephyr ships tf-psa-crypto
 * and the legacy mbedtls_ecp_* / mbedtls_pk_ec() API is gone), a
 * server-authenticated POST to the public claim edge, then a mutually-
 * authenticated GET for the pinned manifest key. The TLS profile that makes the
 * public-edge handshake succeed (P-384 to parse the edge chain, the TLS 1.3
 * ciphersuites, and SNI) lives in the build config; see the SDK Kconfig.
 */
#include "enroll.h"
#include "claim_proto.h"

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/drivers/hwinfo.h>

#include <psa/crypto.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_csr.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

LOG_MODULE_REGISTER(meshanics_enroll, LOG_LEVEL_INF);

#define CLAIM_CA_TAG 0x20 /* server-auth anchor for the claim hop (public edge) */
#define MTLS_TAG     0x21 /* device cert + key + server CA for the mTLS hop */

/* device_id derives a stable per-chip id ("esp32-<hwid hex>") used as the CSR
 * common name and the fleet device name. */
static void device_id(char *out, size_t cap)
{
	uint8_t id[8];
	ssize_t n = hwinfo_get_device_id(id, sizeof(id));
	size_t w = (size_t)snprintf(out, cap, "esp32-");
	for (ssize_t i = 0; i < n && w + 3 <= cap; i++) {
		w += (size_t)snprintf(out + w, cap - w, "%02x", id[i]);
	}
}

/* On-chip EC P-256 key + PKCS#10 CSR. Writes the CSR (PEM) and the private key
 * (PEM, for the subsequent mTLS hop and NVS). The key is generated inside PSA,
 * copied into a transparent PK context (which both signs the CSR and serialises
 * to PEM), and the PSA source key is destroyed. mbedtls_x509write_csr_pem takes
 * no RNG here - PSA supplies the signing nonce. */
static int gen_key_csr(const char *cn, char *csr_pem, size_t csr_cap, char *key_pem, size_t key_cap)
{
	mbedtls_pk_context key;
	mbedtls_x509write_csr req;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
	int rc = -1;

	mbedtls_pk_init(&key);
	mbedtls_x509write_csr_init(&req);

	if (psa_crypto_init() != PSA_SUCCESS) {
		LOG_ERR("psa init");
		goto out;
	}

	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	if (psa_generate_key(&attr, &kid) != PSA_SUCCESS) {
		LOG_ERR("psa keygen");
		goto out;
	}

	if (mbedtls_pk_copy_from_psa(kid, &key) != 0) {
		LOG_ERR("pk copy");
		goto out;
	}

	mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
	char subj[96];
	snprintf(subj, sizeof(subj), "CN=%s", cn);
	if (mbedtls_x509write_csr_set_subject_name(&req, subj) != 0) {
		LOG_ERR("csr subject");
		goto out;
	}
	mbedtls_x509write_csr_set_key(&req, &key);
	if (mbedtls_x509write_csr_pem(&req, (unsigned char *)csr_pem, csr_cap) != 0) {
		LOG_ERR("csr pem");
		goto out;
	}
	if (mbedtls_pk_write_key_pem(&key, (unsigned char *)key_pem, key_cap) != 0) {
		LOG_ERR("key pem");
		goto out;
	}
	rc = 0;
out:
	if (!mbedtls_svc_key_id_is_null(kid)) {
		psa_destroy_key(kid);
	}
	mbedtls_x509write_csr_free(&req);
	mbedtls_pk_free(&key);
	return rc;
}

/* One HTTPS request/response over Zephyr TLS. `tag` selects the registered
 * credentials (server-auth CA for claim, or the full mTLS set). Returns the
 * response length in resp (NUL-terminated), or <0 on a transport error. */
static int https(sec_tag_t tag, const char *host, const char *ip, uint16_t port,
		 const char *request, size_t req_len, char *resp, size_t resp_cap)
{
	int fd = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	if (fd < 0) {
		return -1;
	}
	sec_tag_t tags[] = { tag };
	int verify = TLS_PEER_VERIFY_REQUIRED;
	struct zsock_timeval to = { .tv_sec = 20, .tv_usec = 0 };
	(void)zsock_setsockopt(fd, SOL_TLS, TLS_SEC_TAG_LIST, tags, sizeof(tags));
	(void)zsock_setsockopt(fd, SOL_TLS, TLS_HOSTNAME, host, strlen(host));
	(void)zsock_setsockopt(fd, SOL_TLS, TLS_PEER_VERIFY, &verify, sizeof(verify));
	(void)zsock_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));

	struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	zsock_inet_pton(AF_INET, ip, &addr.sin_addr);
	if (zsock_connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		LOG_WRN("connect/handshake %s:%u errno=%d", host, port, errno);
		zsock_close(fd);
		return -2;
	}
	for (size_t off = 0; off < req_len;) {
		ssize_t s = zsock_send(fd, request + off, req_len - off, 0);
		if (s <= 0) {
			zsock_close(fd);
			return -3;
		}
		off += (size_t)s;
	}
	size_t total = 0;
	for (;;) {
		ssize_t r = zsock_recv(fd, resp + total, resp_cap - 1 - total, 0);
		if (r <= 0) {
			break; /* timeout / closed */
		}
		total += (size_t)r;
		if (total >= resp_cap - 1) {
			break;
		}
	}
	zsock_close(fd);
	resp[total] = '\0';
	return (int)total;
}

/* https() with retry across transport-level failures (n<0). Right after WiFi
 * association the DHCP lease + default route take a moment to settle, so the
 * first connect to a public IP can return EHOSTUNREACH. Any HTTP response
 * (n>0, including a 4xx) is returned immediately - only unreachable-network
 * failures are retried. */
static int https_retry(sec_tag_t tag, const char *host, const char *ip, uint16_t port,
		       const char *request, size_t req_len, char *resp, size_t resp_cap)
{
	int n = -1;
	for (int attempt = 0; attempt < 20; attempt++) {
		n = https(tag, host, ip, port, request, req_len, resp, resp_cap);
		if (n >= 0) {
			return n;
		}
		LOG_WRN("%s:%u unreachable (n=%d), waiting for DHCP/route (retry %d)",
			host, port, n, attempt);
		k_msleep(1000);
	}
	return n;
}

/* http_body returns a pointer to the response body and the parsed status code. */
static const char *http_body(const char *resp, int *status)
{
	*status = 0;
	if (strncmp(resp, "HTTP/1.", 7) == 0) {
		*status = atoi(resp + 9);
	}
	const char *b = strstr(resp, "\r\n\r\n");
	return b ? b + 4 : NULL;
}

int meshanics_enroll(const struct meshanics_provisioning *prov, meshanics_identity *out)
{
	/* One-time path: large buffers are static (single-threaded here) so they do
	 * not blow the agent thread stack. */
	static char csr[1024], body[1024], req[2048], resp[4096], pub_pem[256];
	char id[40];

	if (!prov || !out) {
		return -1;
	}
	memset(out, 0, sizeof(*out));

	device_id(id, sizeof(id));
	LOG_INF("enrolling device %s", id);

	if (gen_key_csr(id, csr, sizeof(csr), out->device_key_pem, sizeof(out->device_key_pem)) != 0) {
		LOG_ERR("on-chip key/CSR generation failed");
		return -1;
	}

	/* --- claim: server-auth TLS to the public edge --- */
	if (tls_credential_add(CLAIM_CA_TAG, TLS_CREDENTIAL_CA_CERTIFICATE,
			       prov->claim_ca, strlen(prov->claim_ca) + 1)) {
		LOG_ERR("register claim CA failed");
		return -1;
	}
	int bl = claim_build_request(prov->claim_token, id, csr, body, sizeof(body));
	if (bl < 0) {
		LOG_ERR("claim request too large");
		return -1;
	}
	int rl = snprintf(req, sizeof(req),
		"POST /api/v1/provision/claim HTTP/1.1\r\nHost: %s\r\n"
		"Content-Type: application/json\r\nContent-Length: %d\r\n"
		"Connection: close\r\n\r\n%s", prov->claim_host, bl, body);
	if (rl <= 0 || rl >= (int)sizeof(req)) {
		return -1;
	}
	int n = https_retry(CLAIM_CA_TAG, prov->claim_host, prov->claim_ip, prov->claim_port,
			    req, (size_t)rl, resp, sizeof(resp));
	int status;
	const char *b = (n > 0) ? http_body(resp, &status) : NULL;
	if (!b || status != 201) {
		LOG_ERR("claim rejected (http %d, n=%d)", b ? status : -1, n);
		return -1;
	}
	if (json_extract_string(b, "device_cert_pem", out->device_cert_pem,
				sizeof(out->device_cert_pem)) <= 0) {
		LOG_ERR("no device certificate in claim response");
		return -1;
	}
	LOG_INF("claimed: received device certificate");

	/* --- manifest-key: mutual TLS with the freshly-claimed identity --- */
	if (tls_credential_add(MTLS_TAG, TLS_CREDENTIAL_CA_CERTIFICATE,
			       prov->server_ca, strlen(prov->server_ca) + 1) ||
	    tls_credential_add(MTLS_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
			       out->device_cert_pem, strlen(out->device_cert_pem) + 1) ||
	    tls_credential_add(MTLS_TAG, TLS_CREDENTIAL_PRIVATE_KEY,
			       out->device_key_pem, strlen(out->device_key_pem) + 1)) {
		LOG_ERR("register claimed credentials failed");
		return -1;
	}
	rl = snprintf(req, sizeof(req),
		"GET /device/manifest-key HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		prov->server_host);
	n = https_retry(MTLS_TAG, prov->server_host, prov->server_ip, prov->artifact_port,
			req, (size_t)rl, resp, sizeof(resp));
	b = (n > 0) ? http_body(resp, &status) : NULL;
	if (!b || status != 200) {
		LOG_ERR("manifest-key fetch failed (http %d, n=%d)", b ? status : -1, n);
		return -1;
	}
	if (json_extract_string(b, "key_id", out->key_id, sizeof(out->key_id)) <= 0 ||
	    json_extract_string(b, "public_key_pem", pub_pem, sizeof(pub_pem)) <= 0) {
		LOG_ERR("no key in manifest-key response");
		return -1;
	}
	if (claim_ed25519_pub_from_pem(pub_pem, out->manifest_pub) != 0) {
		LOG_ERR("manifest key is not a 32-byte Ed25519 SPKI");
		return -1;
	}

	/* Free the provisioning-time credentials now that enrollment is done: the
	 * operational mutual-TLS hops re-register the device identity under their own
	 * tag, and the credential store is small (CONFIG_TLS_MAX_CREDENTIALS_NUMBER),
	 * so leaving these registered would crowd it out. It also keeps the one-time
	 * claim anchor from lingering during normal operation. */
	(void)tls_credential_delete(CLAIM_CA_TAG, TLS_CREDENTIAL_CA_CERTIFICATE);
	(void)tls_credential_delete(MTLS_TAG, TLS_CREDENTIAL_CA_CERTIFICATE);
	(void)tls_credential_delete(MTLS_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE);
	(void)tls_credential_delete(MTLS_TAG, TLS_CREDENTIAL_PRIVATE_KEY);

	LOG_INF("enrolled: pinned manifest key_id=%s", out->key_id);
	return 0;
}
