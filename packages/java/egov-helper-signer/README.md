# egov-helper-signer (Java + Kalkan)

Backend signing service for `@smoker_winston/egov-helper`. Implements the same wire protocol
as the `transport: 'backend'` option in the JS lib, backed by **KalkanCrypt** — NUC RK's
official JCE provider that supports both RSA and the KZ GOST variants.

> Use this when your users have GOST `.p12` files. For RSA-only flows the in-browser path
> is enough and you don't need this service running at all.

---

## What it does

```
Browser                        This service                 NUC RK CAs
─────                          ────────────                 ──────────
pick .p12 + password   ─TLS─►  KeyStore.load("PKCS12", "KALKAN")
                               PrivateKey + X509Certificate
                               CMSSignedDataGenerator
CMS bytes              ◄─TLS─  with CAdES-BES attributes
                               (signingCertificateV2)
```

One endpoint, JSON in / JSON out. Kalkan does the heavy lifting (it knows every KZ GOST
quirk because NUC RK ships it themselves).

---

## Setup

### 1. Get the Kalkan JAR

`libs/` has a README with instructions. Short version:

```
https://sdk.pki.gov.kz/ → sign up → download Java JAR → save as libs/kalkancrypt.jar
```

Allow 1–3 business days for SDK approval.

### 2. Build

```bash
mvn package
```

Produces `target/egov-helper-signer.jar` (shaded, runnable as `java -jar`).

### 3. Run

Locally:

```bash
java -jar target/egov-helper-signer.jar
# listening on http://0.0.0.0:7575
```

Via Docker:

```bash
docker compose up --build
```

---

## Configuration (env vars)

| Variable | Default | What it does |
|---|---|---|
| `PORT` | `7575` | HTTP port |
| `ALLOWED_ORIGIN` | `*` | CORS `Access-Control-Allow-Origin`. **Set to your frontend origin in production.** |
| `MAX_BODY_MB` | `32` | Hard cap on request body size — guards against giant `.p12` or document uploads |
| `REQUIRE_HTTPS` | `false` | When `true`, rejects requests where `X-Forwarded-Proto != https`. Use behind a TLS terminator. |
| `DEBUG_DUMP_REQS` | `false` | Log a redacted summary of each request (size/algo only — never password or bytes) |

---

## API

### `POST /` (and `POST /sign`)

Request:

```json
{
  "p12Base64": "MII...",
  "password": "the user's password",
  "documentBase64": "<base64 of the bytes to sign>",
  "detached": true,
  "hashAlgorithm": "auto"
}
```

`hashAlgorithm` is `"auto"` / `"SHA-256"` / `"SHA-384"` / `"SHA-512"`. For GOST keys the
hash is mandated by the curve size (Stribog-256 for 34.10-2012-256, Stribog-512 for
34.10-2012-512) and this field is ignored.

Response 200:

```json
{
  "signatureBase64": "MII...",
  "signedAtIso": "2026-05-12T10:00:00Z",
  "detached": true,
  "certInfo": {
    "bin": "123456789012",
    "iin": null,
    "commonName": "TEST USER",
    "organization": "ATASUAI LLP",
    "keyUsage": "SIGN",
    "validFromIso": "...",
    "validToIso": "...",
    "serialNumberHex": "...",
    "certificatePem": "-----BEGIN CERTIFICATE-----\\n..."
  }
}
```

Errors (4xx / 5xx):

```json
{ "error": "human-readable message" }
```

Common error messages:

- `Wrong password or corrupted PKCS#12 file` — bad password
- `Missing one of: p12Base64, password, documentBase64` — incomplete request
- `Unsupported public key algorithm: ...` — key uses something neither RSA nor GOST 34.10-2001/2012

### `GET /health`

```json
{ "ok": true, "kalkan": "KALKAN/1.0" }
```

Use for liveness probes. If `kalkan` is `"(not loaded)"`, the JAR is missing from `libs/`.

---

## Wiring to the JS lib

In any consumer (Vue, React, Razor, …):

```ts
import { signDocument } from '@smoker_winston/egov-helper';

const sig = await signDocument(p12File, password, docBytes, {
  transport: 'auto',                                     // RSA stays in-browser
  backendSignUrl: 'https://signer.example.kz/sign',      // GOST routes here
});
```

The JS lib detects whether the key is GOST and only POSTs in that case (so RSA keys still
have the "private key never leaves browser" property).

---

## Security notes

The honest truth: this service is briefly custodian of your users' private keys. We do
everything possible to keep that window tight:

- `.p12` bytes and password are never logged, regardless of `DEBUG_DUMP_REQS`
- Password `char[]` is zeroed in a `finally` block after signing
- No persistence — request bodies live only in memory for one request's lifetime
- Request body size is capped (`MAX_BODY_MB`)
- Default Javalin config has no temp-file upload — JSON is parsed in-memory
- CORS allowlist + HTTPS enforcement are configurable

What you should still do at your deployment:

- Restrict `ALLOWED_ORIGIN` to your real frontend origin in production
- Run behind TLS (nginx/caddy/ALB) and set `REQUIRE_HTTPS=true`
- Rate-limit at the edge (1–5 requests per second per IP is generous for an actual user)
- Audit and disable any access logs that include request bodies
- Run as the unprivileged `egov` user (the Dockerfile already does this)
- For high-volume deployments, prefer mutual TLS over a bearer token shared with your frontend

If you can't accept "backend is briefly custodian," the alternatives are NCALayer (user
install) or SIGEX QR (eGov mobile app on user's phone). There is no third option that
works for KZ GOST keys today.

---

## Versions

- `0.2.0` — initial release. RSA + GOST 34.10-2012 (256 / 512) + GOST 34.10-2001 (legacy).
  Supports CAdES-BES (`signingCertificateV2` attribute embedded). Detached or attached.

---

## License

MIT. The Kalkan JAR you drop into `libs/` is governed by NUC RK's own license — do not
redistribute it.
