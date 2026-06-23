# Security & provisioning model

This document answers the central question: **what is baked into the firmware,
what is provisioned later, and why.**

## Two keys, two owners

Every OTA update is verified **twice**, by two independent keys with two owners:

| Key | Owner | Checked by | Proves |
| --- | --- | --- | --- |
| **MCUboot image-signing key** | **You (the customer)** | the bootloader, at boot | "this image was built by the authorized builder" |
| **Meshanics manifest key** (Ed25519) | **Meshanics** | the agent, before install | "this update was authorized for this fleet, and is fresh" |

You generate your MCUboot key once when you set up a product; its public half is
fused into the bootloader at first flash, so **only firmware you built can ever
boot your devices** — not even Meshanics can push a bootable image you didn't
build. Meshanics holds the manifest signing key (private half sealed server-side)
and the device verifies update authorizations against the **public** half.

These are orthogonal: the manifest signature says *what* is allowed to install and
*when* (with a monotonic anti-rollback counter); the MCUboot signature says the
image is structurally valid and from your build. Both must pass.

## Why the manifest public key is *provisioned*, not *baked*

It is tempting to "set the update key from the control panel when you add a
device." You can — **with one hard rule**:

> A device must never accept a root of trust fetched over an *unauthenticated*
> channel. If a fresh device simply downloaded its update-verification key from
> the network, an attacker who can intercept that first fetch substitutes **their
> own** key, and the device will then happily install attacker-signed firmware.
> This is the classic Trust-On-First-Use (TOFU) hole, and it defeats the entire
> signed-update model.

So you cannot bootstrap trust from nothing over the network — **something** must be
established out-of-band. But that "something" can be *minimal*, and the
update-verification key can ride in on top of it. That is exactly what we do:

- **Baked once, out-of-band (the provisioning bundle):** the control-plane
  address, the **server CA** (so the device can authenticate the control plane and
  detect a MITM), and a **one-time, provisioning-scoped claim credential**. This
  is the minimal root of trust.
- **Provisioned at enrollment, over the authenticated channel:** on first boot the
  device generates its **own** key pair, presents the claim credential over mutual
  TLS (server authenticated by the baked CA), and receives back its **unique
  device certificate** *and* the **manifest public key + key_id**. Both are
  stored in encrypted NVS.

Net effect: the update key *is* "set from the panel on device addition" — it just
arrives over a channel that is already trustworthy because of the small anchor.
The key can also be **rotated** later without reflashing, because it lives in NVS,
not in your image.

## Three layers — nothing secret in your image

| Layer | Contains | Scope | Written |
| --- | --- | --- | --- |
| **Application image** | Zephyr + the agent + **your code** | generic | your build, MCUboot-signed by you |
| **Provisioning bundle** (data partition) | control-plane addr + server CA + claim credential | your account | flash time (WebSerial/USB), from the panel |
| **Identity (NVS)** | device key pair + device cert + manifest public key | per device | first-boot enrollment |

Because the application image is generic and carries no secrets, **one build
serves every device**, and there is no hand-edited key header to get wrong
(the failure mode that previously shipped an all-zeros placeholder key and made a
board unable to verify anything). For local development you may instead compile a
provisioning header (`meshanics_provisioning.h.example`); production uses the
data-partition path written at flash time.

## Verify the key is ours — the Trust Center

The manifest-verification key your devices use is **Meshanics's signing key** for
your account, and we make it independently checkable. Its authoritative value — the
`key_id` and public key — is published on the **Meshanics Trust Center** (the Trust
page), alongside the TUF roots and your account's CA.

Your device reports the `key_id` it was provisioned with (its local status page,
and the panel's device detail). Compare that `key_id` to the value on the Trust
page: if they match, your fleet is trusting the **genuine Meshanics key** — not one
substituted by a tampered provisioning bundle or a man-in-the-middle. The key is
ours, and the trust chain is **auditable, not merely asserted**.

## Transport security is *not* the integrity boundary

The update payload is end-to-end signed (manifest + content digest + anti-rollback
counter) and verified on-device, **independent of transport**. That lets the large
firmware download run over a server-authenticated (not mutually-authenticated)
channel or a short-lived signed URL — cheaper on the device — while the small
identity/enrollment exchange uses mutual TLS. Relaxing transport confidentiality
never weakens payload authenticity or freshness; it only affects who can *observe*
or *delay* a download, which we mitigate separately (signed URLs, rate limits).

## Non-negotiables

- No `--insecure` / verification-optional path, in any build, ever.
- Verify the signature **before** parsing untrusted manifest bytes.
- Isolation: a claim credential is scoped to provisioning only, gated by a
  server-side device allowlist, revocable, and cannot impersonate an
  already-provisioned device or reach another account.
- The anti-rollback counter — not the clock — is the freshness authority.
