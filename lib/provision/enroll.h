/*
 * enroll.h - first-boot self-enrollment: how a factory-fresh device turns the
 * minimal trust anchor in the provisioning config into a unique, control-plane
 * issued identity, without any per-device firmware.
 *
 * On first boot the agent calls this once (WiFi already up); on success it
 * persists the result with meshanics_identity_save() and never enrolls again.
 */
#ifndef MESHANICS_ENROLL_H
#define MESHANICS_ENROLL_H

#include "provisioning.h"
#include "identity.h"

/*
 * meshanics_enroll performs on-device enrollment over the network:
 *   1. generate an EC P-256 key pair + PKCS#10 CSR on-chip (PSA),
 *   2. POST the CSR to the claim endpoint over a server-authenticated TLS
 *      connection (the public edge, verified against prov->claim_ca) presenting
 *      prov->claim_token, and receive a device certificate issued by your
 *      control-plane CA,
 *   3. with that certificate, mutually-authenticate to the control plane and
 *      fetch the pinned manifest-verification key.
 *
 * Fills *out with a complete identity (device cert + key, raw manifest key +
 * key_id). The caller persists it. The device private key never leaves the chip
 * except into *out (-> NVS). Returns 0 on success, <0 on any failure.
 */
int meshanics_enroll(const struct meshanics_provisioning *prov, meshanics_identity *out);

#endif /* MESHANICS_ENROLL_H */
