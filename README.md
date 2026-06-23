 Meshanics MCU Agent SDK

A small Zephyr library that gives any ESP32-class firmware **secure over-the-air
updates, fleet identity, and automatic rollback** - without you writing any of
the update machinery.

You write your application (sensor automation, control logic). You add this
library and call **one function**. You build and sign **your own** firmware. From
then on, Meshanics runs the *fleet update lifecycle* - signed rollouts, canary,
halt-on-metrics, and rollback - against the devices running your image.

> Trust model: **profile
> A** - full TUF stays in the control plane; the device verifies a compact signed
> manifest against a tenant key (see `docs/SECURITY-AND-PROVISIONING.md`). There
> is no `--insecure` path, ever.

## How it works (the developer model)

A microcontroller is not Linux: there are no containers and no dynamic loading -
Zephyr, this agent, and your code are linked into **one firmware image**. 

1. **You** write your business logic and link this agent as a Zephyr module.
2. **You** build and sign your firmware with **your own** MCUboot image key.
3. **Meshanics** issues device identity at enrollment and orchestrates rollouts.
4. New version? You build it, push the artifact to the panel, and Meshanics
   signs the update manifest and rolls it out. The agent already in the field
   pulls it, verifies it, swaps it with MCUboot, and confirms or rolls back.

Two independent signatures protect every update - see Security below.

## Quickstart

Add the module to your `west.yml`:

```yaml
manifest:
  projects:
    - name: meshanics-mcu-sdk
      url: https://github.com/<your-org>/meshanics-mcu-sdk
      revision: main
      path: modules/meshanics
```

Enable it and call it from `main()`:

```c
#include <meshanics/agent.h>

int main(void)
{
    /* Connectivity + identity + signed OTA + rollback, all in a background
     * thread. Returns immediately; your loop is yours. */
    meshanics_agent_start(NULL);

    while (1) {
        if (read_temperature() > 30.0) fan_on();
        meshanics_report_metric("temp_c", read_temperature());
        k_sleep(K_SECONDS(5));
    }
    return 0;
}
```

```ini
# prj.conf
CONFIG_MESHANICS_AGENT=y
CONFIG_MESHANICS_FW_VERSION="1.0.0"   # the version reported to your fleet
```

See `samples/sensor-node/` for a complete buildable example.

## Onboarding a device (no hand-edited keys)

1. In the Meshanics panel, create a **product** for your device family. The panel
   produces a **provisioning bundle** (control-plane address + server CA + a
   one-time, provisioning-scoped claim credential). You never hand-edit keys.
2. Build your firmware (`west build`) - the image is **generic**; it carries no
   tenant secrets.
3. Flash the device: **WebSerial straight from the panel** (no toolchain), or
   over USB. The flasher writes your image **and** the provisioning bundle into a
   data partition.
4. On first boot the device **generates its own key pair**, enrolls, and receives
   a unique identity + the update-verification key over the authenticated channel
   (see Security). It then appears in your fleet - no per-device hand-provisioning.

## Updating the fleet

```
build new image  ->  push artifact to the panel  ->  Meshanics signs the manifest
                                                       + drives the rollout
device polls -> verifies -> downloads -> MCUboot swap -> confirm | rollback
```

## Security (read `docs/SECURITY-AND-PROVISIONING.md`)

- **Your MCUboot image-signing key** - yours. Its public half is fused into the
  bootloader at first flash, so **only firmware you built can boot your devices**.
- **The Meshanics manifest key** - ours, per-tenant. The device verifies every
  update authorization against the tenant public key, which is **provisioned at
  enrollment, not baked into your image**.
- **Root of trust** is established out-of-band (a tiny anchor in the provisioning
  bundle), never fetched unauthenticated at runtime.
- **Verifiable** - the manifest key is Meshanics's, and its `key_id` is published
  on the **Trust Center**. Cross-check the `key_id` your device reports against the
  Trust page to confirm it trusts the genuine key. Trust is auditable, not asserted.

## Layout

```
include/meshanics/agent.h        the public API
lib/                             agent implementation (extracted from the monorepo)
Kconfig, CMakeLists.txt          Zephyr module build wiring
zephyr/module.yml                makes this a Zephyr module
meshanics_provisioning.h.example dev provisioning config template
samples/sensor-node/             a complete reference application
docs/                            security, provisioning, and build guides
```
