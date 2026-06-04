# Per-User Signing Certificate Issuer

This document describes the configuration added by the **pluggable user-certificate issuer**
feature — a way to issue each user's `USER_CERT` signing certificate from an external CA
([step-ca](https://smallstep.com/docs/step-ca/)) instead of the built-in self-signed certificate.

> **Default behaviour is unchanged.** With no configuration, `USER_CERT` is still an
> auto-generated self-signed certificate, exactly as before. The external issuer is strictly
> opt-in.

## Overview

`USER_CERT` is the per-user "Personal Certificate" used by the Shared Signing workflow. Historically
it is always **self-signed** by the instance (trusted only via `serverAsAnchor`). This feature adds a
seam that selects how that certificate is produced:

| Issuer | What it does |
| --- | --- |
| `selfsigned` (default) | The existing self-signed RSA-2048 certificate. No configuration, no outbound calls. |
| `stepca` | Generates a key pair + CSR and enrols the certificate from a step-ca CA over OIDC, so the signature chains to your own PKI. |

When `issuer=stepca`, enrolment happens **at login**: when a user signs in via OIDC, their fresh id
token is used (in their own security context) to request a certificate from step-ca. This is required
because the lazy "create on first signing" path runs under the session owner's context, where the
participant's token is not available. For the default `selfsigned` issuer nothing changes — generation
stays lazy.

**Authentication is not authorization to sign.** A user who merely signs in (e.g. to read documents)
should not be issued a signing certificate. Enrolment is therefore gated on group membership — see
`requiredGroup` below. The gate is *fail-closed*: a missing claim or absent group means no enrolment.

## Environment variables

All settings live under `system.userCertificate.*` in `settings.yml` and follow Stirling's standard
relaxed binding, so each maps to a `SYSTEM_USERCERTIFICATE_*` environment variable (mirroring
`system.serverCertificate.*`).

| Environment variable | `settings.yml` key | Default | Description |
| --- | --- | --- | --- |
| `SYSTEM_USERCERTIFICATE_ISSUER` | `system.userCertificate.issuer` | `selfsigned` | Certificate source: `selfsigned` (default, unchanged) or `stepca`. |
| `SYSTEM_USERCERTIFICATE_CAURL` | `system.userCertificate.caUrl` | _(empty)_ | step-ca base URL, e.g. `https://ca.internal:9000`. **Required when `issuer=stepca`.** |
| `SYSTEM_USERCERTIFICATE_PROVISIONER` | `system.userCertificate.provisioner` | _(empty)_ | step-ca OIDC provisioner name. Informational (diagnostics/logs). |
| `SYSTEM_USERCERTIFICATE_KEYSIZE` | `system.userCertificate.keySize` | `2048` | RSA key size for generated user signing keys. |
| `SYSTEM_USERCERTIFICATE_CABUNDLEPATH` | `system.userCertificate.caBundlePath` | _(empty)_ | Path to a PEM bundle trusted when calling step-ca over TLS. Blank = JVM default trust store. |
| `SYSTEM_USERCERTIFICATE_REQUESTTIMEOUTSECONDS` | `system.userCertificate.requestTimeoutSeconds` | `15` | Connection and read timeout (seconds) for calls to step-ca. |
| `SYSTEM_USERCERTIFICATE_REQUIREDGROUP` | `system.userCertificate.requiredGroup` | _(empty)_ | Only users whose OIDC token lists this group are enrolled a certificate. Blank disables the app-side check (issuance authorization then rests solely with the CA). |
| `SYSTEM_USERCERTIFICATE_REQUIREDGROUPCLAIM` | `system.userCertificate.requiredGroupClaim` | `groups` | Name of the OIDC token claim that lists the user's groups. Read from the **ID token** (the same source step-ca's template gates on). |

## Examples

### Default (no change)

Nothing to set. `USER_CERT` remains self-signed.

### Enrol from step-ca, restricted to a signing group

```yaml
system:
  userCertificate:
    issuer: stepca
    caUrl: https://ca.internal:9000
    provisioner: authentik
    requiredGroup: PDF-Signers
    requiredGroupClaim: groups
    caBundlePath: /configs/step-ca-root.pem   # only if step-ca uses a private TLS root
```

Equivalent environment variables:

```bash
SYSTEM_USERCERTIFICATE_ISSUER=stepca
SYSTEM_USERCERTIFICATE_CAURL=https://ca.internal:9000
SYSTEM_USERCERTIFICATE_PROVISIONER=authentik
SYSTEM_USERCERTIFICATE_REQUIREDGROUP=PDF-Signers
SYSTEM_USERCERTIFICATE_REQUIREDGROUPCLAIM=groups
SYSTEM_USERCERTIFICATE_CABUNDLEPATH=/configs/step-ca-root.pem
```

## Notes and dependencies (CA side)

These are **not** Stirling settings — they are requirements on the CA / identity provider for the
`stepca` issuer to work end-to-end:

- **OIDC token reuse.** Stirling forwards the user's existing OIDC id token to step-ca's `/1.0/sign`
  endpoint as the one-time token. It does **not** run an interactive browser flow, so no client secret
  is involved on Stirling's side. The token's audience must match step-ca's configured OIDC
  `clientID` (use the same OIDC application Stirling logs in with).
- **Groups in the ID token.** Both the Stirling-side gate (`requiredGroup`) and the authoritative
  step-ca template gate read groups from the **id token**, not the userinfo endpoint. Ensure the
  identity provider includes the `groups` claim in the id token.
- **Authoritative gate on step-ca.** The Stirling-side `requiredGroup` check is an optimization (avoid
  calling the CA for non-members and keep logs quiet). The binding authorization should also be
  enforced on the CA — e.g. a leaf template that fails when the required group is absent.
- **Long-term validity (TSA/LTV).** step-ca leaves are typically short-lived; for PDF signatures to
  remain valid after expiry, enable RFC 3161 timestamping. This is outside the scope of this feature.
