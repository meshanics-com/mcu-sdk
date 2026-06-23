/*
 * claim_proto.h - pure, host-testable helpers for the claim/enrollment HTTP
 * protocol: building the request body and reading fields out of the JSON
 * responses. No network, crypto, or platform dependency - just (de)serialization,
 * which is the easy-to-get-wrong part, so it is tested on the host.
 *
 * Flow these support (first boot):
 *   POST /api/v1/provision/claim  {claim_token, device_id, csr_pem}
 *     -> {device_cert_pem, ca_cert_pem, device_host, ...}
 *   GET  /device/manifest-key (mutual TLS, once the cert above is in hand)
 *     -> {key_id, public_key_pem, alg}
 */
#ifndef MESHANICS_CLAIM_PROTO_H
#define MESHANICS_CLAIM_PROTO_H

#include <stddef.h>
#include <stdint.h>

/*
 * claim_build_request writes the JSON body for POST /provision/claim into out.
 * csr_pem typically contains newlines; they (and quotes/backslashes) are
 * JSON-escaped. Returns the body length, or -1 if it does not fit in cap.
 */
int claim_build_request(const char *claim_token, const char *device_id,
			const char *csr_pem, char *out, size_t cap);

/*
 * json_extract_string copies the value of a top-level string field from a flat
 * JSON object into out, decoding \n, \t, \r, \", \\ and \/ escapes (enough for
 * PEM payloads). out is NUL-terminated. Returns the decoded length, or -1 if the
 * field is missing, malformed, or does not fit in cap.
 *
 * This is deliberately a minimal scanner for the small, server-generated objects
 * this agent receives - not a general JSON parser.
 */
int json_extract_string(const char *json, const char *field, char *out, size_t cap);

/*
 * claim_ed25519_pub_from_pem decodes a PEM-encoded Ed25519 SubjectPublicKeyInfo
 * (what GET /device/manifest-key returns in "public_key_pem") into the raw 32-byte
 * public key the on-device manifest verifier pins.
 *
 * An Ed25519 SPKI is a fixed 44-byte DER structure: a 12-byte prefix
 * (SEQUENCE / AlgorithmIdentifier with OID 1.3.101.112 / BIT STRING header)
 * followed by the 32-byte key. This base64-decodes the body, checks that exact
 * prefix, and copies the trailing 32 bytes - so the device never needs an X.509 /
 * ASN.1 parser to consume its provisioned key. Returns 0 on success, or -1 if the
 * PEM is malformed or is not a 32-byte Ed25519 key.
 */
int claim_ed25519_pub_from_pem(const char *pem, uint8_t out[32]);

#endif /* MESHANICS_CLAIM_PROTO_H */
