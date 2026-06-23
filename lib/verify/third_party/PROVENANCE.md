# Vendored third-party crypto

The manifest verifier's Ed25519 primitive and its SHA-512 are vendored here so
the agent builds standalone (host test suite and ESP32-S3 device) without
depending on whatever crypto the RTOS happens to expose. Both are MIT-licensed
and were copied **from the trusted MCUboot tree already on disk** — the same code
MCUboot uses to verify its own ED25519-signed images — not fetched from the
network.

## Source

- Workspace: `~/zephyrproject` (Zephyr v4.4.99)
- MCUboot: `bootloader/mcuboot`, commit `511dc9e28f223d6b158740b66a702209531361ff`

| File(s) | Copied from (under `bootloader/mcuboot/`) | License |
| --- | --- | --- |
| `fiat/curve25519.c`, `curve25519.h`, `curve25519_tables.h` | `ext/fiat/src/`, `ext/fiat/src/` | MIT (`fiat/LICENSE`) |
| `tinycrypt/source/sha512.c`, `include/tinycrypt/sha512.h` | `ext/tinycrypt-sha512/lib/{source,include}` | MIT (`tinycrypt/LICENSE`) |
| `tinycrypt/source/utils.c`, `include/tinycrypt/{utils.h,constants.h}` | `ext/tinycrypt/lib/{source,include}` | MIT |

`fiat/curve25519.c` provides `ED25519_verify` (BoringSSL/Fiat-Crypto API). Fiat
parts are machine-generated, formally verified field arithmetic; the Ed25519
glue derives from SUPERCOP ref10 (public domain). SHA-512 comes from tinycrypt
(`MCUBOOT_USE_MBED_TLS` is left undefined, so the tinycrypt branch is used).

## Local modifications

Kept to the absolute minimum and confined to one line:

- `fiat/curve25519.c`: replaced `#include <bootutil/bootutil_public.h>` with
  `#include <assert.h>`. The file uses **no** symbol from `bootutil_public.h`
  (verified by grep) — that include only coupled it to the MCUboot build — and it
  does need `assert()`. The change is marked inline with a "Meshanics vendoring
  patch" comment.

No other files are modified.

## Why this is acceptable supply-chain-wise

These are not arbitrary downloads: they are MIT-licensed components already part
of the user's installed, trusted MCUboot, and the agent's own host conformance
test (`make agent-mcu-test`) exercises this exact crypto against the shared
vectors — a valid signature must accept and every tampered/wrong-key vector must
reject — so a substitution would fail the build.

## Updating

Re-copy from the same MCUboot paths, re-apply the one-line patch, and re-run
`make agent-mcu-test`.
