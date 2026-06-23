/*
 * provisioning.c - DEV/bring-up backend for the provisioning config: reads the
 * compile-time header meshanics_provisioning.h (copied from the .example and
 * filled in from the panel; gitignored because it carries the WiFi PSK and the
 * claim credential).
 *
 * This is the only file that includes that header, so the production backend -
 * which reads the same fields from a data partition written at flash time - is a
 * single-file swap. The rest of the agent depends only on provisioning.h.
 */
#include "provisioning.h"

/* If the integrator has not provided meshanics_provisioning.h yet, the agent
 * still compiles; meshanics_provisioning_get() returns NULL and the agent reports
 * "not provisioned" at runtime rather than failing the build with a missing
 * header. */
#if defined(__has_include)
#  if __has_include("meshanics_provisioning.h")
#    define MESHANICS_HAVE_PROVISIONING 1
#  endif
#endif

#ifdef MESHANICS_HAVE_PROVISIONING
#include "meshanics_provisioning.h"

static const struct meshanics_provisioning prov = {
	.wifi_ssid      = MESHANICS_WIFI_SSID,
	.wifi_psk       = MESHANICS_WIFI_PSK,

	.claim_host     = MESHANICS_CLAIM_HOST,
	.claim_ip       = MESHANICS_CLAIM_IP,
	.claim_port     = MESHANICS_CLAIM_PORT,
	.claim_ca       = MESHANICS_CLAIM_CA,
	.claim_token    = MESHANICS_CLAIM_TOKEN,

	.server_host    = MESHANICS_SERVER_HOST,
	.server_ip      = MESHANICS_SERVER_IP,
	.artifact_port  = MESHANICS_ARTIFACT_PORT,
	.fleet_port     = MESHANICS_FLEET_PORT,
	.server_ca      = MESHANICS_SERVER_CA,

	.artifact_name  = MESHANICS_ARTIFACT_NAME,
	.target_profile = MESHANICS_TARGET_PROFILE,
};

const struct meshanics_provisioning *meshanics_provisioning_get(void)
{
	return &prov;
}
#else
const struct meshanics_provisioning *meshanics_provisioning_get(void)
{
	return 0; /* not provisioned */
}
#endif
