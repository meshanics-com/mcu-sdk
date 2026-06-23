/*
 * ed25519_fiat.c - the manifest verifier's Ed25519 backend.
 *
 * Wraps Fiat-Crypto's ED25519_verify (third_party/fiat/curve25519.c), the
 * formally-verified, public-domain/MIT Ed25519 that MCUboot itself uses to
 * verify ED25519-signed images. The SAME code runs on the host test suite
 * and on the ESP32-S3, so the host test exercises exactly the device crypto.
 * SHA-512 (required by Ed25519) is provided by the vendored tinycrypt.
 */
#include "ed25519.h"

/* Provided by third_party/fiat/curve25519.c (BoringSSL/Fiat-Crypto API).
 * Returns 1 on a valid signature, 0 otherwise. */
extern int ED25519_verify(const uint8_t *message, size_t message_len,
			  const uint8_t signature[64], const uint8_t public_key[32]);

int md_ed25519_verify(const uint8_t pub[32], const uint8_t *msg, size_t msg_len,
		      const uint8_t sig[64])
{
	return ED25519_verify(msg, msg_len, sig, pub) == 1 ? 1 : 0;
}
