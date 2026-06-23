/*
 * ed25519.h - the one platform-specific seam in the manifest verifier.
 *
 * The verifier logic (manifest_verify.c) is portable; the Ed25519 primitive is
 * provided by ed25519_fiat.c, which wraps the vendored Fiat-Crypto ED25519_verify
 * (third_party/) - the formally-verified, MIT-licensed code MCUboot itself uses.
 * The SAME backend runs on the host test suite and on the device, so the
 * host test exercises exactly the device crypto (pure Ed25519, RFC 8032).
 */
#ifndef MESHANICS_ED25519_H
#define MESHANICS_ED25519_H

#include <stddef.h>
#include <stdint.h>

/*
 * Returns 1 iff sig (64 bytes) is a valid pure-Ed25519 signature by pub
 * (32-byte raw public key) over msg[0..msg_len). Returns 0 on any failure.
 * Verification of a public signature need not be constant time.
 */
int md_ed25519_verify(const uint8_t pub[32], const uint8_t *msg, size_t msg_len,
		      const uint8_t sig[64]);

#endif /* MESHANICS_ED25519_H */
