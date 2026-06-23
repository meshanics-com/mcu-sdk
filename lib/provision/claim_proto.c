/*
 * claim_proto.c - see claim_proto.h. Pure C, no platform/network/crypto deps.
 */
#include "claim_proto.h"

#include <string.h>

/* Append s to out[*w..cap), JSON-escaping the characters that must be escaped in
 * a JSON string. Returns 0 on success, -1 if it would overflow. */
static int append_escaped(char *out, size_t cap, size_t *w, const char *s)
{
	for (; *s; s++) {
		const char *esc = NULL;
		char buf[3];
		switch (*s) {
		case '"':  esc = "\\\""; break;
		case '\\': esc = "\\\\"; break;
		case '\n': esc = "\\n";  break;
		case '\r': esc = "\\r";  break;
		case '\t': esc = "\\t";  break;
		default:
			buf[0] = *s;
			buf[1] = '\0';
			esc = buf;
			break;
		}
		size_t n = strlen(esc);
		if (*w + n >= cap) {
			return -1;
		}
		memcpy(out + *w, esc, n);
		*w += n;
	}
	return 0;
}

static int append_raw(char *out, size_t cap, size_t *w, const char *s)
{
	size_t n = strlen(s);
	if (*w + n >= cap) {
		return -1;
	}
	memcpy(out + *w, s, n);
	*w += n;
	return 0;
}

int claim_build_request(const char *claim_token, const char *device_id,
			const char *csr_pem, char *out, size_t cap)
{
	if (!claim_token || !device_id || !csr_pem || !out || cap == 0) {
		return -1;
	}
	size_t w = 0;
	if (append_raw(out, cap, &w, "{\"claim_token\":\"") ||
	    append_escaped(out, cap, &w, claim_token) ||
	    append_raw(out, cap, &w, "\",\"device_id\":\"") ||
	    append_escaped(out, cap, &w, device_id) ||
	    append_raw(out, cap, &w, "\",\"csr_pem\":\"") ||
	    append_escaped(out, cap, &w, csr_pem) ||
	    append_raw(out, cap, &w, "\"}")) {
		return -1;
	}
	out[w] = '\0';
	return (int)w;
}

/* Locate the value of "field" in a flat JSON object: find the quoted key, then
 * the ':' and the opening quote of the value. Returns a pointer just past that
 * opening quote, or NULL. Only matches keys, not values, by requiring the match
 * to be immediately followed by '"' then optional spaces then ':'. */
static const char *find_value_start(const char *json, const char *field)
{
	size_t flen = strlen(field);
	for (const char *p = json; (p = strchr(p, '"')) != NULL; p++) {
		if (strncmp(p + 1, field, flen) == 0 && p[1 + flen] == '"') {
			const char *q = p + 1 + flen + 1; /* past closing key quote */
			while (*q == ' ' || *q == '\t') {
				q++;
			}
			if (*q != ':') {
				continue;
			}
			q++;
			while (*q == ' ' || *q == '\t') {
				q++;
			}
			if (*q != '"') {
				return NULL; /* value is not a string */
			}
			return q + 1;
		}
	}
	return NULL;
}

int json_extract_string(const char *json, const char *field, char *out, size_t cap)
{
	if (!json || !field || !out || cap == 0) {
		return -1;
	}
	const char *v = find_value_start(json, field);
	if (!v) {
		return -1;
	}
	size_t w = 0;
	for (; *v && *v != '"'; v++) {
		char c;
		if (*v == '\\') {
			v++;
			switch (*v) {
			case 'n':  c = '\n'; break;
			case 't':  c = '\t'; break;
			case 'r':  c = '\r'; break;
			case '"':  c = '"';  break;
			case '\\': c = '\\'; break;
			case '/':  c = '/';  break;
			case '\0': return -1; /* trailing backslash */
			default:   c = *v;   break;
			}
		} else {
			c = *v;
		}
		if (w + 1 >= cap) {
			return -1;
		}
		out[w++] = c;
	}
	if (*v != '"') {
		return -1; /* unterminated string */
	}
	out[w] = '\0';
	return (int)w;
}

/* base64 sextet value for c, or -1 for a non-alphabet character. */
static int b64val(char c)
{
	if (c >= 'A' && c <= 'Z') {
		return c - 'A';
	}
	if (c >= 'a' && c <= 'z') {
		return c - 'a' + 26;
	}
	if (c >= '0' && c <= '9') {
		return c - '0' + 52;
	}
	if (c == '+') {
		return 62;
	}
	if (c == '/') {
		return 63;
	}
	return -1;
}

/* The fixed 12-byte DER prefix of an Ed25519 SubjectPublicKeyInfo:
 *   SEQUENCE(42) { SEQUENCE(5) { OID 1.3.101.112 } BIT STRING(33) { 00 <32 key> } } */
static const uint8_t ED25519_SPKI_PREFIX[12] = {
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
};

int claim_ed25519_pub_from_pem(const char *pem, uint8_t out[32])
{
	if (!pem || !out) {
		return -1;
	}
	const char *b = strstr(pem, "-----BEGIN");
	if (!b) {
		return -1;
	}
	b = strchr(b, '\n'); /* skip to the end of the BEGIN line */
	if (!b) {
		return -1;
	}
	b++;
	const char *e = strstr(b, "-----END");
	if (!e) {
		return -1;
	}

	/* Decode the base64 body between the markers, ignoring whitespace/newlines.
	 * An Ed25519 SPKI is exactly 44 bytes; cap the buffer just past that so a
	 * longer (wrong-type) key is rejected rather than overrun. */
	uint8_t der[48];
	size_t dlen = 0;
	int acc = 0, nbits = 0;
	for (const char *p = b; p < e; p++) {
		if (*p == '=') {
			break; /* padding: end of data */
		}
		int v = b64val(*p);
		if (v < 0) {
			continue; /* whitespace / newline */
		}
		acc = (acc << 6) | v;
		nbits += 6;
		if (nbits >= 8) {
			nbits -= 8;
			if (dlen >= sizeof(der)) {
				return -1; /* longer than any 32-byte SPKI: not ours */
			}
			der[dlen++] = (uint8_t)((acc >> nbits) & 0xff);
		}
	}

	if (dlen != 12 + 32 || memcmp(der, ED25519_SPKI_PREFIX, sizeof(ED25519_SPKI_PREFIX)) != 0) {
		return -1; /* not a 32-byte Ed25519 public key */
	}
	memcpy(out, der + sizeof(ED25519_SPKI_PREFIX), 32);
	return 0;
}
