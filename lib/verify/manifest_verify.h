/*
 * manifest_verify.h - on-device verification of the compact signed update
 * manifest (trust profile A).
 *
 * Portable C, covered by a host conformance vector set so the device's notion of
 * "a valid update" is fixed and testable.
 *
 * The only platform-specific piece is the Ed25519 primitive (md_ed25519_verify
 * in ed25519.h): an OpenSSL backend for host tests, PSA/mbedTLS on the device.
 * Everything here - protobuf decode, the domain-separated preimage, the ordered
 * checks, the field validation - runs unchanged on both.
 *
 * Memory safety matters: md_verify parses attacker-controlled bytes (the outer
 * SignedManifest) BEFORE the signature is checked, so every read is bounds
 * checked and nothing is allocated. The inner manifest is only decoded AFTER the
 * signature verifies.
 */
#ifndef MESHANICS_MANIFEST_VERIFY_H
#define MESHANICS_MANIFEST_VERIFY_H

#include <stddef.h>
#include <stdint.h>

/* Frozen domain-separation prefix. The signature covers MD_SIGN_CONTEXT
 * followed by the exact manifest bytes. */
#define MD_SIGN_CONTEXT "meshanics:device-manifest:v1\n"

/* Length of MD_SIGN_CONTEXT, a compile-time constant (so the preimage buffer is
 * a fixed-size array, not a VLA). */
#define MD_SIGN_CONTEXT_LEN (sizeof(MD_SIGN_CONTEXT) - 1)

/* Manifest layout version this verifier understands (CompactUpdateManifest
 * schema_version). A device rejects any other value rather than misparse. */
#define MD_SCHEMA_VERSION 1

/* Upper bound on the inner manifest size we will verify. The real manifest is
 * ~100 bytes; this bounds the stack preimage buffer and rejects anything absurd
 * before it can matter. */
#define MD_MAX_MANIFEST 512

/* The per-tenant signing key the device pins: the raw 32-byte Ed25519 public
 * key plus its key_id (lowercase hex of sha256(DER PKIX), NUL-terminated). The
 * device is provisioned with both, so it compares key_id as a string and never
 * needs DER/x509 on-device. */
typedef struct {
	const uint8_t *pub;  /* 32 bytes */
	const char *key_id;  /* NUL-terminated hex */
} md_pinned_key;

/* Decoded CompactUpdateManifest. String fields point INTO the caller's buffer
 * (not NUL-terminated); they are valid only while that buffer lives. */
typedef struct {
	uint32_t schema_version;
	const char *tenant_id;        size_t tenant_id_len;
	const char *artifact_name;    size_t artifact_name_len;
	const char *artifact_version; size_t artifact_version_len;
	const char *sha256;           size_t sha256_len;
	uint64_t size_bytes;
	const char *target_profile;   size_t target_profile_len;
	uint64_t rollback_counter;
	int64_t issued_at_unix;
} md_manifest;

typedef enum {
	MD_OK = 0,
	MD_ERR_DECODE,          /* malformed protobuf (outer or inner) */
	MD_ERR_ALG,             /* alg != "ed25519" */
	MD_ERR_SIG_SIZE,        /* signature not 64 bytes */
	MD_ERR_EMPTY_MANIFEST,  /* no manifest bytes */
	MD_ERR_MANIFEST_TOO_BIG,/* manifest exceeds MD_MAX_MANIFEST */
	MD_ERR_KEY_ID,          /* key_id does not match the pinned key */
	MD_ERR_SIGNATURE,       /* Ed25519 verification failed */
	MD_ERR_SCHEMA,          /* unsupported schema_version */
	MD_ERR_FIELD,           /* a manifest field invariant failed */
} md_result;

/*
 * md_verify checks a received SignedManifest (raw proto bytes) against the
 * pinned key and, on MD_OK, fills *out with the decoded manifest (pointers into
 * buf). It uses a fixed order of checks:
 * alg -> signature size -> key_id -> signature -> decode+validate the manifest.
 * The signature is verified BEFORE the inner manifest is decoded.
 *
 * md_verify does NOT enforce anti-rollback (that needs device-held state); after
 * MD_OK, call md_check_rollback with the last counter the device applied.
 */
md_result md_verify(const md_pinned_key *key, const uint8_t *buf, size_t len, md_manifest *out);

/* Returns 1 iff incoming strictly exceeds last_applied (anti-rollback). Pass 0
 * for last_applied when the device has never applied a manifest. */
int md_check_rollback(uint64_t last_applied, uint64_t incoming);

/* Human-readable name for a result code (for logs/tests). */
const char *md_result_str(md_result r);

#endif /* MESHANICS_MANIFEST_VERIFY_H */
