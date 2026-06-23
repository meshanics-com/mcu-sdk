/*
 * identity.h - the per-device identity established at first-boot enrollment and
 * persisted in NVS. This is what makes one generic application image serve every
 * device: nothing here is compiled in; it is generated/fetched on first boot.
 *
 * It holds (a) the device's own mutual-TLS certificate + private key, issued by
 * your control-plane CA in response to the on-chip CSR, and (b) the pinned
 * update-verification key: the raw 32-byte Ed25519 public key plus its key_id, so
 * the manifest verifier needs no X.509/ASN.1 on the device.
 *
 * At-rest protection of the private key is the device's flash encryption (enable
 * ESP32-S3 flash encryption in production, which transparently encrypts NVS); see
 * docs/SECURITY-AND-PROVISIONING.md.
 */
#ifndef MESHANICS_IDENTITY_H
#define MESHANICS_IDENTITY_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
	char device_cert_pem[1024]; /* mutual-TLS client certificate (PEM) */
	char device_key_pem[512];   /* its private key (PEM) */
	uint8_t manifest_pub[32];   /* raw Ed25519 manifest-verification key */
	char key_id[80];            /* key_id of the above (lowercase hex, NUL-term) */
} meshanics_identity;

/* meshanics_identity_exists returns true once a complete identity is stored (the
 * first-boot enrollment has completed). */
bool meshanics_identity_exists(void);

/* meshanics_identity_load fills *out from NVS. Returns 0 on success, <0 if no
 * complete identity is stored or a record is unreadable. */
int meshanics_identity_load(meshanics_identity *out);

/* meshanics_identity_save persists *id to NVS. Returns 0 on success. */
int meshanics_identity_save(const meshanics_identity *id);

#endif /* MESHANICS_IDENTITY_H */
