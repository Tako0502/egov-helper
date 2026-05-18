# Postman collection — egov-helper-signer + eGov Mobile QR

End-to-end test collection for the Java signing service and the SIGEX QR + eGov Mobile flow. Lets a teammate verify every code path the JS library calls without writing any frontend code.

## Files

| File | What it is |
|---|---|
| `EGOVHelper.postman_collection.json` | Collection — all requests, organised into three folders |
| `EGOVHelper.postman_environment.example.json` | Environment template — committed to git. Copy and fill in your own `.p12` + password. |
| `EGOVHelper.postman_environment.json` | Your local environment with the real cert. **Gitignored** — never push this file. |

## Setup

1. **Start the signer locally** — from `packages/java/egov-helper-signer/`:
   ```bash
   mvn package
   java -jar target/egov-helper-signer.jar
   # listening on http://0.0.0.0:7575
   ```
   Or `docker compose up --build`.

2. **Import into Postman**:
   - Drag in `EGOVHelper.postman_collection.json` (everyone uses the same one).
   - For the environment: copy `EGOVHelper.postman_environment.example.json` to `EGOVHelper.postman_environment.json` and fill in your own `p12Base64` + `p12Password` (run `base64 -i your-cert.p12` to get the base64 string). The real-values file is gitignored — keep it that way.
   - In Postman's top-right environment picker, select the imported environment.

3. **Sanity check**: run `1. Backend (Kalkan signer) > GET /health` — expect `{ ok: true, kalkan: "KALKAN/0.7" }`.

## Folders

### 1. Backend (Kalkan signer)

Direct requests against the Java service.

| Request | What it tests |
|---|---|
| `GET /health` | Service is up + Kalkan JAR is loaded |
| `POST /sign` | Full signing path — loads the .p12, signs `documentBase64`, returns CMS. Test script captures the CMS into `{{cmsBase64}}` so you can chain `/cms/inspect` next. |
| `POST /info` | BIN-match precheck — same body as `/sign`, returns just the cert subject. Captures BIN/IIN into env. |
| `POST /cms/inspect` | Parses a CMS blob, returns the signer's cert. Used by `checkBinViaQr` after the QR flow returns. |
| `POST /cms/verify` | Full cryptographic verification — answers "did THIS user sign THIS document?" Returns `signatureValid`, `documentDigestMatches`, `certValidAtSigningTime` independently. Pre-flight: run `/sign` first so `{{cmsBase64}}` + `{{documentBase64}}` are populated. |
| `POST /cms/verify (legal doc)` | Same endpoint, alternate body shape. Pass `{role, type, version, language}` instead of `documentBase64` — the signer service fetches the canonical PDF from `LEGAL_DOC_BASE_URL` and verifies against that. Requires `LEGAL_DOC_BASE_URL` env var on the server. |

### 2. QR + eGov Mobile (SIGEX hub)

Walks the protocol of the public SIGEX hub at `https://sigex.kz` from Postman. Run order: register → submit data → scan QR → poll.

| Request | What it does |
|---|---|
| `POST /api/egovQr` | Opens a new QR session. Captures `qrCode`, `dataURL`, `signURL`, `eGovMobileLaunchLink` into env. |
| `POST {{dataURL}}` | Uploads the doc to sign. Triggers the QR. |
| `GET {{signURL}}` | Poll until `signatures: [...]` arrives. Captures first signature into `{{cmsBase64}}`. |

To actually sign, render `{{qrCode}}` (base64 PNG) somewhere visible — paste it into [base64-image.de](https://www.base64-image.de/) or just drop it into a browser address bar as `data:image/png;base64,<paste>`. Then scan with eGov Mobile.

If you're on the same device as the phone, open `{{eGovMobileLaunchLink}}` (an `egovmobile://...` deeplink) instead — eGov Mobile opens directly.

### 3. Full identity check via QR (chained)

The complete `checkBinViaQr()` flow. After running 2's three requests (which leave a CMS in `{{cmsBase64}}`), set `{{expectedBin}}` to the BIN you expect, then run `Step 5 — POST /cms/inspect + BIN match`. The test script asserts the typed BIN/IIN matches what's in the cert.

## Environment variables

Pre-filled with real values:

- `signerBaseUrl` — `http://localhost:7575` (override if you're running the signer elsewhere)
- `sigexBaseUrl` — `https://sigex.kz`
- `p12Base64` — real Elorda.com GOST-512 cert, base64-encoded **(secret)**
- `p12Password` — `Z857hazah142*&` **(secret)**
- `documentBase64` — base64 of `"Hello, eGov-Helper smoke test 2026!"`. Swap for any base64 payload.
- `expectedBin` — *empty by default*. Run `POST /info` once to see the cert's actual BIN/IIN, then paste it here to make folder 3's assertion fire.

Populated by the collection's test scripts:

- `cmsBase64`, `certBin`, `certIin` — set by `/sign` and `/info`
- `qrCode`, `dataURL`, `signURL`, `eGovMobileLaunchLink`, `eGovBusinessLaunchLink` — set by `POST /api/egovQr`

## ⚠️ Do not commit the environment file with the real password

The repo's `.gitignore` blocks `*.p12` / `*.pfx` / `*.pem` / `*.key`, but **JSON files containing the base64 of a `.p12` are not blocked**. The environment file in this directory has the Elorda.com cert and password embedded in plain text so teammates can run it immediately.

Recommended workflow:

- **Share the environment via Postman's team workspace or a private channel**, not git.
- **Add the environment file to `.gitignore`** before pushing:
  ```bash
  echo "packages/java/egov-helper-signer/postman/EGOVHelper.postman_environment.json" >> .gitignore
  ```
  (Or delete the embedded password and require teammates to fill it themselves.)

The collection file (`EGOVHelper.postman_collection.json`) is safe to commit — it only references variables.

## Notes on GOST vs RSA

The Elorda.com cert is **GOST-512**. That matters because:

- `POST /sign` and `POST /info` work — Kalkan handles GOST natively. This is the whole reason the Java backend exists.
- The pure-browser RSA path (`signDocument` with `transport: 'browser'`) **cannot** use this cert and would throw at parseP12 time. Don't add a "browser-only sign" request to this collection — there's nothing to test.
- The SIGEX QR flow doesn't care about the key type at all — eGov Mobile signs with whatever key the user has installed in the app on their phone.
