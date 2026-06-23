# lib/ — agent implementation

The agent implementation behind the stable public API in
`include/meshanics/agent.h`. Most integrators never need to read this — you use
the library through the header and `meshanics_agent_start()`.

| Component | Role |
| --- | --- |
| manifest verifier | verifies a compact update manifest's signature **before** parsing it, against the pinned key (Ed25519 + SHA-512), with strict anti-rollback checks |
| OTA logic | Content-Range parsing, chunk planning, and the boot-confirm decision — the pure, host-testable core of an update |
| platform layer | WiFi + mutually-authenticated TLS to the control plane, block-wise firmware download, staging to the inactive slot with a digest check, the MCUboot swap, and the persisted anti-rollback counters |

Identity and the manifest-verification key are **not** compiled into the image:
they are provisioned at first-boot enrollment and stored in encrypted NVS, from a
minimal trust anchor in the provisioning bundle (see
`../docs/SECURITY-AND-PROVISIONING.md`).

The verifier is covered by a conformance suite so the device's notion of "a valid
update" cannot drift — keep that coverage in place when changing it.
