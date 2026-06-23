# lib/ — agent implementation (extraction map)

The verified on-device implementation already exists and is **proven on metal**
in the Meshanics monorepo. This SDK assembles it behind the stable
`include/meshanics/agent.h` API. As each module is vendored in, uncomment its
sources in the top-level `CMakeLists.txt`.

| SDK path (target) | Monorepo source | Role |
| --- | --- | --- |
| `lib/meshanics_agent.c` | new (this repo) | public API + agent thread + lifecycle state machine |
| `lib/verify/` | `agent/mcu/verify/` (`manifest_verify.*`, `ed25519_fiat.c`, `third_party/`) | verify-before-parse manifest verifier (Fiat Ed25519 + SHA-512); shares the cross-agent conformance vectors |
| `lib/ota/` | `agent/mcu/ota/` | pure OTA logic: Content-Range parse, chunk planner, boot-confirm decision (host-unit-tested) |
| `lib/plat/plat_net.c` | `agent/mcu/app/src/plat_net.c` | WiFi + mTLS fetch of manifest + block-wise firmware download |
| `lib/plat/plat_mcuboot.c` | `agent/mcu/app/src/plat_mcuboot.c` | stage to slot 1 + PSA SHA-256 check + `boot_request_upgrade` + confirm/revert |
| `lib/plat/plat_counter.c` | `agent/mcu/app/src/plat_counter.c` | NVS-backed applied/pending/failed anti-rollback counters |

### What changes during extraction (vs the monorepo reference app)

- **Identity & manifest key move out of the image.** The reference app baked
  `pinned_key.h` (footgun). The SDK provisions the manifest public key + device
  identity at enrollment into NVS, from a minimal baked anchor (the provisioning
  bundle). See `../docs/SECURITY-AND-PROVISIONING.md`.
- **`main.c` becomes the customer's**, not ours. The agent loop + HTTP status +
  register/heartbeat fold into `meshanics_agent.c` behind `meshanics_agent_start()`.
- **Config via Kconfig**, not edited headers (`CONFIG_MESHANICS_*`).

The conformance test (`agent/mcu/test`, CI job `mcu-verify`) must continue to gate
`lib/verify/` so the device and the Go reference can never disagree on "what is a
valid update".
