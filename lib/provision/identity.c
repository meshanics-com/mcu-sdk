/*
 * identity.c - persist/restore the enrolled device identity in NVS, through the
 * shared plat_store mount. See identity.h.
 */
#include "identity.h"
#include "plat_store.h"

#include <string.h>

/* NVS record ids for identity. Disjoint from the counter ids (1..3) so they
 * share the `storage` partition without collision. */
#define ID_CERT  10
#define ID_KEY   11
#define ID_PUB   12
#define ID_KEYID 13

bool meshanics_identity_exists(void)
{
	return plat_store_exists(ID_CERT) && plat_store_exists(ID_KEY) &&
	       plat_store_exists(ID_PUB) && plat_store_exists(ID_KEYID);
}

/* load_str reads a string record into out[0..cap), NUL-terminating at the stored
 * length. Returns 0 on success, -1 if absent or it does not fit. */
static int load_str(uint16_t id, char *out, size_t cap)
{
	int n = plat_store_read(id, out, cap - 1);
	if (n <= 0 || n >= (int)cap) {
		return -1;
	}
	out[n] = '\0';
	return 0;
}

int meshanics_identity_load(meshanics_identity *out)
{
	if (!out) {
		return -1;
	}
	memset(out, 0, sizeof(*out));

	if (load_str(ID_CERT, out->device_cert_pem, sizeof(out->device_cert_pem)) != 0 ||
	    load_str(ID_KEY, out->device_key_pem, sizeof(out->device_key_pem)) != 0 ||
	    load_str(ID_KEYID, out->key_id, sizeof(out->key_id)) != 0) {
		return -1;
	}
	if (plat_store_read(ID_PUB, out->manifest_pub, sizeof(out->manifest_pub)) !=
	    (int)sizeof(out->manifest_pub)) {
		return -1;
	}
	return 0;
}

int meshanics_identity_save(const meshanics_identity *id)
{
	if (!id) {
		return -1;
	}
	/* Strings are stored without their NUL (restored on load by length); the
	 * manifest key is exactly 32 raw bytes. */
	if (plat_store_write(ID_CERT, id->device_cert_pem, strlen(id->device_cert_pem)) != 0 ||
	    plat_store_write(ID_KEY, id->device_key_pem, strlen(id->device_key_pem)) != 0 ||
	    plat_store_write(ID_KEYID, id->key_id, strlen(id->key_id)) != 0 ||
	    plat_store_write(ID_PUB, id->manifest_pub, sizeof(id->manifest_pub)) != 0) {
		return -1;
	}
	return 0;
}
