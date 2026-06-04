# Per-User Signing Certificate Issuer

Configuration for the **pluggable user-certificate issuer** — a way to issue each user's
`USER_CERT` signing certificate from an external CA ([step-ca](https://smallstep.com/docs/step-ca/))
instead of the built-in self-signed certificate.

> **Scope.** This documents the **Stirling-PDF application** side: the config/env vars, the issuer
> seam, and the runtime behaviour. It is **not** a CA setup or intermediate-issuance ceremony — for
> that (constraints, `certreq`, NTAuth containment, etc.) see the CA-side runbooks referenced under
> [Notes and dependencies (CA side)](#notes-and-dependencies-ca-side).

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
| `SYSTEM_USERCERTIFICATE_PROVISIONER` | `system.userCertificate.provisioner` | _(empty)_ | step-ca OIDC provisioner name. Informational (diagnostics/logs). **The id token's audience (`aud`) must equal this provisioner's `clientID` in step-ca** — use the same OIDC application Stirling logs in with. |
| `SYSTEM_USERCERTIFICATE_KEYSIZE` | `system.userCertificate.keySize` | `2048` | RSA key size for generated user signing keys. |
| `SYSTEM_USERCERTIFICATE_CABUNDLEPATH` | `system.userCertificate.caBundlePath` | _(empty)_ | Path to a PEM bundle trusted when calling step-ca over TLS. Blank = JVM default trust store. |
| `SYSTEM_USERCERTIFICATE_REQUESTTIMEOUTSECONDS` | `system.userCertificate.requestTimeoutSeconds` | `15` | Connection and read timeout (seconds) for calls to step-ca. |
| `SYSTEM_USERCERTIFICATE_REQUIREDGROUP` | `system.userCertificate.requiredGroup` | _(empty)_ | Only users whose OIDC token lists this group are enrolled a certificate. Blank disables the app-side check (issuance authorization then rests solely with the CA). |
| `SYSTEM_USERCERTIFICATE_REQUIREDGROUPCLAIM` | `system.userCertificate.requiredGroupClaim` | `groups` | Name of the OIDC token claim that lists the user's groups. Read from the **ID token** (the same source step-ca's template gates on). |

## Certificate lifetime and renewal

Externally issued leaves are typically **short-lived**, and they can only be (re-)issued **at login**
— signing runs outside the user's OIDC context, so there is no re-mint at signing time. The behaviour
is therefore:

- **At login** — the certificate is (re-)enrolled when it is **missing, already expired, or in the
  last third of its validity window**. A user who logs in regularly always has a fresh certificate.
- **At signing** — if the stored certificate has expired, signing is **refused with a clear error**
  (`…has expired`). It does **not** silently fall back to a self-signed certificate, which would
  substitute a different identity. The user must log in again to re-enrol.
- **Enrolment never blocks login.** If step-ca is unreachable (or anything else fails) during login,
  the login still succeeds; the failure is logged and retried at the next login. Re-enrolment simply
  overwrites the stored certificate, which is safe — existing PDF signatures embed their own
  certificate and validate against that, not against the stored row.
- **Concurrent logins don't duplicate.** `user_id` is unique in the database: two simultaneous
  first-logins of the same user resolve to a single certificate (the losing insert is a no-op logged
  at debug), and any later re-enrolment is an in-place overwrite.

**Consequence for the CA configuration:** the leaf lifetime must comfortably exceed the typical
interval between a user's logins, or a returning user could find an expired certificate before the
next login refreshes it. As a guide: **7–30 days** for daily users, or **~90 days** conservatively.
Pair short leaves with RFC 3161 timestamping (below) so signatures remain valid after the leaf expires.

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

- **Group claim must be in the ID token, and sourced from your directory.** Both the Stirling-side
  gate (`requiredGroup`) and the authoritative step-ca template gate read groups from the **id token**,
  not the userinfo endpoint — ensure the identity provider includes the `groups` claim in the id
  token. For a single source of truth, the IdP should derive those groups from your directory (e.g.
  Authentik syncing groups from an AD/LDAP source), so `requiredGroup` matches the same group your CA
  enrolment policy uses.

- **Authoritative gate on step-ca.** The Stirling-side `requiredGroup` check is an optimization (avoid
  calling the CA for non-members and keep logs quiet). The binding authorization must also be enforced
  on the CA — e.g. a leaf template that `fail`s when the required group is absent from `.Token.groups`.

- **Leaf template requirements.** The issued leaf must be a valid document-signing certificate that
  also satisfies any constraints on step-ca's intermediate (EKUs and name constraints intersect along
  the chain). Concretely the leaf template must:
  - set a **subject DN consistent with the intermediate's name constraints** — if the intermediate
    permits a `dirName` subtree (e.g. `O=<your org>`), the leaf subject **must** include it, or the
    whole chain fails to validate (a CN-only subject is outside the permitted subtree);
  - carry the **document-signing EKUs** via `unknownExtKeyUsage` (the same set the intermediate is
    constrained to, so the chain EKU intersection is non-empty): `1.3.6.1.5.5.7.3.36`
    (RFC 9336 documentSigning), `1.3.6.1.4.1.311.10.3.12` (MS Document Signing), `1.2.840.113583.1.1.5`
    (Adobe PDF);
  - set **keyUsage** `digitalSignature` + `contentCommitment` (smallstep's template name for the
    `nonRepudiation` bit);
  - enable **CRL over HTTP** and set `crlDistributionPoints` on the leaf, so revocation info can be
    embedded for LTV.

- **Long-term validity (TSA/LTV).** step-ca leaves are short-lived; for PDF signatures to remain valid
  after the leaf expires, enable **RFC 3161 timestamping** at signing time. This is mandatory for the
  short-lived-leaf model, and is outside the scope of this feature.

> **AstraTeam deployment.** The constrained-intermediate ceremony, the exact `policy.inf`, the
> `PDF-Signers` group, and the leaf-template/EKU decisions are recorded in the infra repo:
> `stepca-intermediate-policy.inf` and `doc-signing.md` (swarm `docs/CA/`). Configure step-ca from
> those; this document only covers the Stirling side.
