/* Host test for claim_proto. Build + run: see the bottom of this file. */
#include "../claim_proto.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(cond, msg)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("FAIL: %s\n", msg);                             \
			failures++;                                            \
		}                                                              \
	} while (0)

int main(void)
{
	char buf[1024];

	/* Build a request; a CSR with newlines must come out JSON-escaped. */
	const char *csr = "-----BEGIN CERTIFICATE REQUEST-----\n"
			  "MIIBezCCASEC\n"
			  "-----END CERTIFICATE REQUEST-----\n";
	int n = claim_build_request("mesh_abc123", "esp32-aabbcc", csr, buf, sizeof(buf));
	CHECK(n > 0, "build_request returns length");
	CHECK(strstr(buf, "\"claim_token\":\"mesh_abc123\"") != NULL, "token present");
	CHECK(strstr(buf, "\"device_id\":\"esp32-aabbcc\"") != NULL, "device_id present");
	CHECK(strstr(buf, "\\n") != NULL, "csr newlines escaped as \\n");
	CHECK(strstr(buf, "\n-----END") == NULL || strstr(buf, "csr_pem") != NULL,
	      "no raw newline inside the JSON value region");

	/* Round-trip: extracting csr_pem from the request restores the CSR. */
	char rt[512];
	int m = json_extract_string(buf, "csr_pem", rt, sizeof(rt));
	CHECK(m == (int)strlen(csr), "round-trip csr length matches");
	CHECK(strcmp(rt, csr) == 0, "round-trip csr bytes match (newlines restored)");

	/* Parse a claim response: PEM fields with escaped newlines decode back. */
	const char *resp =
		"{\"device_cert_pem\":\"-----BEGIN CERTIFICATE-----\\nAAAA\\n"
		"-----END CERTIFICATE-----\\n\",\"ca_cert_pem\":\"CA\\n\","
		"\"device_host\":\"ota.meshanics.com\"}";
	char cert[512], host[128];
	int c = json_extract_string(resp, "device_cert_pem", cert, sizeof(cert));
	CHECK(c > 0, "device_cert_pem extracted");
	CHECK(strncmp(cert, "-----BEGIN CERTIFICATE-----\n", 28) == 0,
	      "device_cert_pem newline decoded");
	CHECK(strstr(cert, "\n-----END CERTIFICATE-----\n") != NULL, "cert end decoded");
	CHECK(json_extract_string(resp, "device_host", host, sizeof(host)) == 17 &&
	      strcmp(host, "ota.meshanics.com") == 0, "device_host extracted");

	/* Manifest-key response. */
	const char *mk = "{\"alg\":\"ed25519\",\"key_id\":\"abc123de\",\"public_key_pem\":\"K\\n\"}";
	char kid[128];
	CHECK(json_extract_string(mk, "key_id", kid, sizeof(kid)) == 8 &&
	      strcmp(kid, "abc123de") == 0, "key_id extracted");

	/* Missing field and overflow are rejected, not silently truncated. */
	CHECK(json_extract_string(resp, "nope", buf, sizeof(buf)) == -1, "missing field -> -1");
	CHECK(json_extract_string(resp, "device_cert_pem", cert, 4) == -1, "overflow -> -1");
	CHECK(claim_build_request("t", "d", csr, buf, 10) == -1, "request overflow -> -1");

	/* A bare key substring must not match a value (key-only matching). */
	const char *tricky = "{\"x\":\"key_id is not a key here\",\"key_id\":\"real\"}";
	char v[64];
	CHECK(json_extract_string(tricky, "key_id", v, sizeof(v)) == 4 && strcmp(v, "real") == 0,
	      "matches the key, not a value substring");

	/* Ed25519 SPKI PEM -> raw 32 bytes. The vector below is a valid SPKI whose
	 * key is the bytes 0x00..0x1f, so the decode is checkable byte-for-byte. */
	const char *ed_pem =
		"-----BEGIN PUBLIC KEY-----\n"
		"MCowBQYDK2VwAyEAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n"
		"-----END PUBLIC KEY-----\n";
	uint8_t pub[32];
	int ok = claim_ed25519_pub_from_pem(ed_pem, pub);
	CHECK(ok == 0, "ed25519 SPKI PEM decodes");
	int seq_ok = 1;
	for (int i = 0; i < 32; i++) {
		if (pub[i] != (uint8_t)i) {
			seq_ok = 0;
		}
	}
	CHECK(seq_ok, "decoded key bytes are 0x00..0x1f");

	/* The real path: extract public_key_pem out of a manifest-key response (escaped
	 * newlines) and decode it - the exact two steps the agent runs at enrollment. */
	const char *mk_full =
		"{\"alg\":\"ed25519\",\"key_id\":\"abc123de\",\"public_key_pem\":"
		"\"-----BEGIN PUBLIC KEY-----\\n"
		"MCowBQYDK2VwAyEAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\\n"
		"-----END PUBLIC KEY-----\\n\"}";
	char pem_buf[256];
	CHECK(json_extract_string(mk_full, "public_key_pem", pem_buf, sizeof(pem_buf)) > 0,
	      "public_key_pem extracted from manifest-key response");
	uint8_t pub2[32];
	CHECK(claim_ed25519_pub_from_pem(pem_buf, pub2) == 0 && memcmp(pub, pub2, 32) == 0,
	      "extracted PEM decodes to the same key");

	/* A non-Ed25519 / malformed key is rejected, not silently truncated. */
	uint8_t junk[32];
	CHECK(claim_ed25519_pub_from_pem(
		"-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----\n", junk) == -1,
	      "too-short SPKI rejected");
	CHECK(claim_ed25519_pub_from_pem("not a pem at all", junk) == -1, "non-PEM rejected");

	if (failures == 0) {
		printf("RESULT: PASS (claim_proto)\n");
		return 0;
	}
	printf("RESULT: FAIL (%d)\n", failures);
	return 1;
}
