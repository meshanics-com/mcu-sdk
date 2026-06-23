/*
 * sensor-node - a complete reference app showing the Meshanics MCU SDK DX.
 *
 * Your business logic is the star; the agent runs OTA + identity + rollback in
 * the background. You build and sign THIS firmware; Meshanics rolls out updates.
 */
#include <meshanics/agent.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(sensor_node, LOG_LEVEL_INF);

/* Replace these with your real drivers. */
static double read_temperature(void) { return 24.5; }
static void   fan_set(bool on)        { ARG_UNUSED(on); }

static void on_state(meshanics_state st, void *user)
{
	ARG_UNUSED(user);
	LOG_INF("meshanics: state -> %d", (int)st);
}

int main(void)
{
	const meshanics_config cfg = {
		.on_state = on_state,
		/* .firmware_version defaults to CONFIG_MESHANICS_FW_VERSION */
	};

	if (meshanics_agent_start(&cfg) != MESHANICS_OK) {
		LOG_ERR("meshanics agent failed to start");
	}

	/* Your control loop. The agent thread handles connectivity + updates. */
	while (1) {
		double t = read_temperature();
		fan_set(t > 30.0);
		meshanics_report_metric("temp_c", t);
		k_sleep(K_SECONDS(5));
	}
	return 0;
}
