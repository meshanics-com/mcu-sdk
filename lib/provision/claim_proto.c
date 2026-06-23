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
