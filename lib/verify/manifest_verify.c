/*
 * manifest_verify.c - portable C verifier for the compact signed update
 * manifest. Mirrors the reference verifier.
 *
 * No heap, no platform headers beyond the C string functions; the only external
 * dependency is md_ed25519_verify (ed25519.h). The protobuf decoders here are
 * hand-written and minimal - only the two message shapes we use - and every read
 * is bounds checked because the outer SignedManifest is parsed before its
 * signature is verified.
 */
#include "manifest_verify.h"
#include "ed25519.h"

#include <string.h>

/* read_varint advances *pos past a base-128 varint, returning its value in *out.
 * Returns -1 on truncation or a >64-bit value. */
static int read_varint(const uint8_t *buf, size_t len, size_t *pos, uint64_t *out)
{
	uint64_t result = 0;
	int shift = 0;
	while (*pos < len && shift < 64) {
		uint8_t b = buf[(*pos)++];
		result |= (uint64_t)(b & 0x7f) << shift;
		if ((b & 0x80) == 0) {
			*out = result;
			return 0;
		}
		shift += 7;
	}
	return -1;
}

/* skip_field advances *pos past a field of the given wire type whose tag was
 * already consumed. Length-delimited payloads are handled by the callers (they
 * want the bytes), so this only skips varint/fixed wire types. */
static int skip_scalar(const uint8_t *buf, size_t len, size_t *pos, uint32_t wire)
{
	switch (wire) {
	case 0: { /* varint */
		uint64_t v;
		return read_varint(buf, len, pos, &v);
	}
	case 5: /* 32-bit */
		if (len - *pos < 4) return -1;
		*pos += 4;
		return 0;
	case 1: /* 64-bit */
		if (len - *pos < 8) return -1;
		*pos += 8;
		return 0;
	default:
		return -1; /* groups (3,4) and unknown wire types are rejected */
	}
}

/* next_len_delimited reads a wire-type-2 length prefix and yields the slice. */
static int read_len_delimited(const uint8_t *buf, size_t len, size_t *pos,
			      const uint8_t **slice, size_t *slice_len)
{
	uint64_t flen;
	if (read_varint(buf, len, pos, &flen)) return -1;
	if (flen > (uint64_t)(len - *pos)) return -1;
	*slice = buf + *pos;
	*slice_len = (size_t)flen;
	*pos += (size_t)flen;
	return 0;
}

static md_result decode_signed(const uint8_t *buf, size_t len,
			       const uint8_t **manifest, size_t *manifest_len,
			       const char **key_id, size_t *key_id_len,
			       const char **alg, size_t *alg_len,
			       const uint8_t **sig, size_t *sig_len)
{
	*manifest = NULL; *manifest_len = 0;
	*key_id = NULL; *key_id_len = 0;
	*alg = NULL; *alg_len = 0;
	*sig = NULL; *sig_len = 0;

	size_t pos = 0;
	while (pos < len) {
		uint64_t tag;
		if (read_varint(buf, len, &pos, &tag)) return MD_ERR_DECODE;
		uint32_t field = (uint32_t)(tag >> 3);
		uint32_t wire = (uint32_t)(tag & 7);
		if (wire == 2) {
			const uint8_t *fp;
			size_t flen;
			if (read_len_delimited(buf, len, &pos, &fp, &flen)) return MD_ERR_DECODE;
			switch (field) {
			case 1: *manifest = fp; *manifest_len = flen; break;
			case 2: *key_id = (const char *)fp; *key_id_len = flen; break;
			case 3: *alg = (const char *)fp; *alg_len = flen; break;
			case 4: *sig = fp; *sig_len = flen; break;
			default: break; /* ignore unknown fields */
			}
		} else if (skip_scalar(buf, len, &pos, wire)) {
			return MD_ERR_DECODE;
		}
	}
	return MD_OK;
}

static md_result decode_manifest(const uint8_t *buf, size_t len, md_manifest *m)
{
	memset(m, 0, sizeof(*m));
	size_t pos = 0;
	while (pos < len) {
		uint64_t tag;
		if (read_varint(buf, len, &pos, &tag)) return MD_ERR_DECODE;
		uint32_t field = (uint32_t)(tag >> 3);
		uint32_t wire = (uint32_t)(tag & 7);
		if (wire == 0) {
			uint64_t v;
			if (read_varint(buf, len, &pos, &v)) return MD_ERR_DECODE;
			switch (field) {
			case 1: m->schema_version = (uint32_t)v; break;
			case 6: m->size_bytes = v; break;
			case 8: m->rollback_counter = v; break;
			case 9: m->issued_at_unix = (int64_t)v; break;
			default: break;
			}
		} else if (wire == 2) {
			const uint8_t *fp;
			size_t flen;
			if (read_len_delimited(buf, len, &pos, &fp, &flen)) return MD_ERR_DECODE;
			switch (field) {
			case 2: m->tenant_id = (const char *)fp; m->tenant_id_len = flen; break;
			case 3: m->artifact_name = (const char *)fp; m->artifact_name_len = flen; break;
			case 4: m->artifact_version = (const char *)fp; m->artifact_version_len = flen; break;
			case 5: m->sha256 = (const char *)fp; m->sha256_len = flen; break;
			case 7: m->target_profile = (const char *)fp; m->target_profile_len = flen; break;
			default: break;
			}
		} else if (skip_scalar(buf, len, &pos, wire)) {
			return MD_ERR_DECODE;
		}
	}
	return MD_OK;
}

static int is_lower_hex64(const char *s, size_t n)
{
	if (n != 64) return 0;
	for (size_t i = 0; i < n; i++) {
		char c = s[i];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
	}
	return 1;
}

static md_result validate_manifest(const md_manifest *m)
{
	if (m->schema_version != MD_SCHEMA_VERSION) return MD_ERR_SCHEMA;
	if (m->tenant_id_len == 0) return MD_ERR_FIELD;
	if (m->artifact_name_len == 0) return MD_ERR_FIELD;
	if (m->artifact_version_len == 0) return MD_ERR_FIELD;
	if (!is_lower_hex64(m->sha256, m->sha256_len)) return MD_ERR_FIELD;
	if (m->size_bytes == 0) return MD_ERR_FIELD;
	if (m->target_profile_len == 0) return MD_ERR_FIELD;
	return MD_OK;
}

md_result md_verify(const md_pinned_key *key, const uint8_t *buf, size_t len, md_manifest *out)
{
	const uint8_t *manifest, *sig;
	const char *key_id, *alg;
	size_t manifest_len, key_id_len, alg_len, sig_len;

	md_result r = decode_signed(buf, len, &manifest, &manifest_len,
				    &key_id, &key_id_len, &alg, &alg_len, &sig, &sig_len);
	if (r != MD_OK) return r;

	/* Fixed order: alg, sizes, key_id, signature, then the
	 * inner manifest - the manifest bytes are decoded only after the signature
	 * is verified. */
	if (alg_len != 7 || memcmp(alg, "ed25519", 7) != 0) return MD_ERR_ALG;
	if (sig_len != 64) return MD_ERR_SIG_SIZE;
	if (manifest_len == 0) return MD_ERR_EMPTY_MANIFEST;
	if (manifest_len > MD_MAX_MANIFEST) return MD_ERR_MANIFEST_TOO_BIG;

	size_t kid_len = strlen(key->key_id);
	if (key_id_len != kid_len || memcmp(key_id, key->key_id, kid_len) != 0) return MD_ERR_KEY_ID;

	/* preimage = MD_SIGN_CONTEXT || manifest bytes */
	uint8_t preimage[MD_SIGN_CONTEXT_LEN + MD_MAX_MANIFEST];
	memcpy(preimage, MD_SIGN_CONTEXT, MD_SIGN_CONTEXT_LEN);
	memcpy(preimage + MD_SIGN_CONTEXT_LEN, manifest, manifest_len);
	if (!md_ed25519_verify(key->pub, preimage, MD_SIGN_CONTEXT_LEN + manifest_len, sig)) return MD_ERR_SIGNATURE;

	md_manifest m;
	r = decode_manifest(manifest, manifest_len, &m);
	if (r != MD_OK) return r;
	r = validate_manifest(&m);
	if (r != MD_OK) return r;

	*out = m;
	return MD_OK;
}

int md_check_rollback(uint64_t last_applied, uint64_t incoming)
{
	return incoming > last_applied ? 1 : 0;
}

const char *md_result_str(md_result r)
{
	switch (r) {
	case MD_OK: return "ok";
	case MD_ERR_DECODE: return "decode";
	case MD_ERR_ALG: return "alg";
	case MD_ERR_SIG_SIZE: return "sig_size";
	case MD_ERR_EMPTY_MANIFEST: return "empty_manifest";
	case MD_ERR_MANIFEST_TOO_BIG: return "manifest_too_big";
	case MD_ERR_KEY_ID: return "key_id";
	case MD_ERR_SIGNATURE: return "signature";
	case MD_ERR_SCHEMA: return "schema";
	case MD_ERR_FIELD: return "field";
	default: return "unknown";
	}
}
