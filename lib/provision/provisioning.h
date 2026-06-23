/*
 * provisioning.h - the device's out-of-band ROOT OF TRUST, read through one
 * accessor so the rest of the agent never cares where it came from.
 *
 * This is the minimal config a factory-fresh device needs to authenticate the
 * control plane and enroll itself: WiFi, the control-plane hosts/ports, the trust
 * anchors, and a one-time claim credential. It deliberately does NOT contain any
 * per-device identity or the update-verification key - those are generated/fetched
 * at first-boot enrollment and stored in NVS (see identity.h).
 *
 * Two backends implement meshanics_provisioning_get():
 *   - provisioning.c    : reads a compile-time header (meshanics_provisioning.h),
 *                         the dev/bring-up convenience.
 *   - (production)      : reads a data partition written at flash time (WebSerial
 *                         / USB), so one generic application image serves every
 *                         device. Swapping backends touches only that one file.
 *
 * Connection model: the proven networking path dials the control plane by IP and
 * presents `host` for SNI + certificate-name verification, so each endpoint here
 * carries both. (DNS resolution is a planned enhancement; see the SDK docs.)
 */
#ifndef MESHANICS_PROVISIONING_H_API
#define MESHANICS_PROVISIONING_H_API

#include <stdint.h>

struct meshanics_provisioning {
	/* Network to join. */
	const char *wifi_ssid;
	const char *wifi_psk;

	/* Enrollment hop: the public control-plane edge, authenticated against
	 * claim_ca (a public root, e.g. the CA that issues the edge's certificate).
	 * claim_token is the one-time, provisioning-scoped credential presented once
	 * to receive a unique device certificate. */
	const char *claim_host;
	const char *claim_ip;
	uint16_t    claim_port;
	const char *claim_ca;     /* PEM */
	const char *claim_token;

	/* Operational hops: the device-facing control plane, reached over mutual TLS
	 * with the certificate received at enrollment and authenticated against
	 * server_ca (your control-plane CA). One host serves both ports:
	 *   artifact_port - signed manifest, manifest-verification key, firmware
	 *   fleet_port    - device register + heartbeat */
	const char *server_host;
	const char *server_ip;
	uint16_t    artifact_port;
	uint16_t    fleet_port;
	const char *server_ca;    /* PEM */

	/* The update stream this device tracks: the firmware artifact name and the
	 * hardware/target profile the control plane matches rollout targets against. */
	const char *artifact_name;
	const char *target_profile;
};

/*
 * meshanics_provisioning_get returns the active provisioning config, or NULL if
 * the device has not been provisioned (no trust anchor present). The returned
 * pointer and its strings are valid for the lifetime of the program.
 */
const struct meshanics_provisioning *meshanics_provisioning_get(void);

#endif /* MESHANICS_PROVISIONING_H_API */
