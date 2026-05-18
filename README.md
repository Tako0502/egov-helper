# @smoker_winston/egov-helper

> Sign Kazakhstan e-Gov documents from any web app — without NCALayer.

[![npm](https://img.shields.io/npm/v/@smoker_winston/egov-helper.svg)](https://www.npmjs.com/package/@smoker_winston/egov-helper)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Three signing flows in one tiny TypeScript library:

| Flow | What the user does | Works for |
|---|---|---|
| **`.p12` signing** | Picks file + types password | RSA + GOST (anything NUC RK issues) |
| **eGov Mobile (QR / deeplink)** | Scans QR or taps a link | Any key registered in eGov Mobile |
| **Inspect** | Pastes a CMS blob | Reading existing signatures |

The library itself is a 14 KB HTTP client. The cryptographic heavy lifting happens in a small Java service ([`packages/java/egov-helper-signer/`](packages/java/egov-helper-signer/)) that wraps NUC RK's official [KalkanCrypt](https://pki.gov.kz/) provider — the only library that knows every KZ algorithm variant correctly.

---

## How it works

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Your web app (browser)                        │
│  npm install @smoker_winston/egov-helper                             │
└──────────────────────────────────────────────────────────────────────┘
              │                                  │
              │  .p12 + password                 │  no .p12 needed
              ▼                                  ▼
┌──────────────────────────────┐    ┌──────────────────────────────────┐
│  Your Kalkan signer service  │    │   SIGEX hub  (sigex.kz, public)  │
│  (Java, Docker, you run it)  │    │                                  │
│  packages/java/egov-helper-  │    │   ↕  user's phone (eGov Mobile)  │
│         signer/              │    │      scans QR / opens deeplink   │
└──────────────────────────────┘    └──────────────────────────────────┘
              │                                  │
              ▼                                  ▼
    CMS / CAdES-BES bytes              CMS / CAdES-BES bytes
              │                                  │
              └──────────────┬───────────────────┘
                             ▼
        Send to your storage backend for verification with
             Tako0502.EgovHelper (.NET) or KalkanCrypt
```

---

## Install

```bash
npm install @smoker_winston/egov-helper
```

For backend signature verification in .NET:

```bash
dotnet add package Tako0502.EgovHelper
```

That's it for the library side. To actually run the `.p12`-signing flow, you also need a Kalkan signer service somewhere — see [Backend setup](#backend-setup) below.

---

## Quick start

All three flows return the same `SignResult` / `CertInfo` shape, so the downstream code (verify, store, audit) is identical.

### 1. Check that a typed BIN matches the user's `.p12`

```ts
import { checkBin } from '@smoker_winston/egov-helper';

const result = await checkBin(p12File, password, '190440033661', {
  backendUrl: 'http://your-signer.example.kz',
});

if (!result.match) {
  alert(`That key belongs to ${result.certBin ?? result.certIin}, not 190440033661.`);
}
```

### 2. Sign a document with `.p12`

```ts
import { signDocument } from '@smoker_winston/egov-helper';

const contract = await loadContract();              // Uint8Array
const sig = await signDocument(p12File, password, contract, {
  backendUrl: 'http://your-signer.example.kz',
  detached: true,                                   // default
  hashAlgorithm: 'SHA-256',                         // RSA only; GOST mandates Stribog
});

// Send to your storage endpoint:
await fetch('/api/contracts/store', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    contractId,
    signatureBase64: sig.signatureBase64,
    signerBin: sig.certInfo.bin,
    signerName: sig.certInfo.commonName,
    signedAt: sig.signedAt.toISOString(),
  }),
});
```

### 3. Sign via eGov Mobile (no `.p12`, no password)

```ts
import { signDocumentViaQr, isLikelyMobile } from '@smoker_winston/egov-helper';

const sig = await signDocumentViaQr(contract, {
  description: 'Contract #C-12345',
  documentName: 'contract.pdf',
  onQrReady: (qr) => {
    if (isLikelyMobile()) {
      // On phones, open eGov Mobile directly via deeplink.
      window.location.href = qr.eGovMobileLink;
    } else {
      // On desktop, render the QR for the user to scan with their phone.
      document.getElementById('qr-img').setAttribute('src', qr.qrCodeDataUrl);
    }
  },
  onDataSent: () => setStatus('Waiting for signature on your phone…'),
  // Optional: replace SIGEX's logo in the QR centre with your own brand.
  logo: { src: '/img/my-logo.svg', size: 0.22, borderRadius: 8 },
});

// Same result shape — same downstream code.
```

### 4. Inspect a signature (decode CMS into human-readable fields)

```ts
import { inspectSignature } from '@smoker_winston/egov-helper';

const info = await inspectSignature(signatureBase64, { document: contractBytes });
console.log(info.signers[0].certInfo.commonName);   // who signed it
console.log(info.signers[0].signedAt);              // when
console.log(info.documentDigestMatches);            // true if the doc wasn't tampered with
```

> **Note**: `inspectSignature` works in-browser for RSA-signed CMS. For GOST CMS verification, use the .NET package `Tako0502.EgovHelper` (which speaks both).

---

## Backend setup

### Run the Kalkan signer locally

You need this for the `signDocument` and `checkBin` flows. (`signDocumentViaQr` uses SIGEX, so no local backend.)

#### One-time: get the Kalkan JARs

Kalkan is NUC RK's official JCE provider. It can't be redistributed, so each developer / operator gets their own copy:

1. Go to <https://sdk.pki.gov.kz/> and sign up.
2. **Submit the developer-access form** (separate from account creation — without it you only get a public-preview SDK with empty 0-byte JARs).
3. Wait 1–3 business days for approval.
4. Download the approved SDK (`.7z` despite the name; on macOS extract with `brew install unar && unar SDK.7z`).
5. Drop the JARs into `packages/java/egov-helper-signer/libs/`:
   - `knca_provider_jce_kalkan-0.7.5.jar`
   - `knca_provider_util-0.8.5.jar`

#### Run it

```bash
docker compose up --build
```

The service starts on <http://localhost:7676>. Hit `/health` to verify:

```bash
curl http://localhost:7676/health
# {"ok":true,"kalkan":"KALKAN/0.7"}
```

Now point your frontend's `backendUrl` at it.

### Run in production

The Docker image is stateless — put it behind your TLS terminator (nginx/caddy/ALB), set environment variables, scale horizontally:

| Variable | Recommended |
|---|---|
| `ALLOWED_ORIGIN` | Your real frontend origin (`https://app.example.kz`). **Don't leave as `*`.** |
| `REQUIRE_HTTPS` | `true` |
| `MAX_BODY_MB` | `8` (sane upper bound for contracts) |
| `DEBUG_DUMP_REQS` | `false` |

Full deployment guide: [`packages/java/egov-helper-signer/README.md`](packages/java/egov-helper-signer/README.md).

### Backend verification

Whichever flow you use, you'll want to verify the resulting CMS on your server before trusting it. The .NET companion package ships with the NUC RK root CAs bundled:

```csharp
using Tako0502.EgovHelper;
using System.Linq;

var result = EgovSignatureVerifier.Verify(signature, document, new VerifyOptions
{
    ValidateCertificateChain = true,
    TrustedRoots = EgovTrustRoots.Rsa.Concat(EgovTrustRoots.Gost).ToList(),
});

if (!result.Valid) return BadRequest(result.Signers.FirstOrDefault()?.SignatureError);
if (result.Signers[0].CertInfo.Bin != expectedBin) return Forbid();
```

Full .NET docs: [`packages/dotnet/EgovHelper.Net/README.md`](packages/dotnet/EgovHelper.Net/README.md).

---

## Examples

Copy-paste-ready code for the common stacks:

| Folder | Stack |
|---|---|
| [`examples/vue/`](examples/vue) | Vite + Vue 3 + TypeScript |
| [`examples/react/`](examples/react) | Vite + React 18 + TypeScript |
| [`examples/razor-mvc/`](examples/razor-mvc) | ASP.NET Core MVC — drop-in Controller + Razor view + JS snippet |
| [`examples/plain-html/`](examples/plain-html) | Single HTML file with a `<script>` tag — no build step |

CLI for ops / debugging:

```bash
npx @smoker_winston/egov-helper info --p12 cert.p12 --pwd pass --backend http://localhost:7676
npx @smoker_winston/egov-helper sign --p12 cert.p12 --pwd pass --doc contract.pdf --backend http://localhost:7676 --out contract.cms
npx @smoker_winston/egov-helper inspect --sig contract.cms --doc contract.pdf
```

OpenAPI spec for non-JS clients (Go, Python, mobile): [`packages/java/egov-helper-signer/openapi.yaml`](packages/java/egov-helper-signer/openapi.yaml).

---

## API reference

### Functions

| Function | Returns |
|---|---|
| `checkBin(p12, password, typedBin, options)` | `Promise<CheckBinResult>` |
| `signDocument(p12, password, content, options)` | `Promise<SignResult>` |
| `signDocumentViaQr(content, options)` | `Promise<QrSignResult>` |
| `inspectSignature(input, options?)` | `Promise<SignatureInspection>` |
| `addTimestamp(signature, options)` | `Promise<Uint8Array>` — upgrade to CAdES-T |
| `isLikelyMobile()` | `boolean` — UA + media-query detection |

### Key types

```ts
interface SignResult {
  signature: Uint8Array;          // CMS / PKCS#7 SignedData (DER)
  signatureBase64: string;        // same bytes, base64
  signedAt: Date;
  detached: boolean;
  certInfo: CertInfo;             // BIN, IIN, CN, validity, etc.
}

interface CertInfo {
  bin: string | null;             // 12-digit BIN of the legal entity
  iin: string | null;             // 12-digit IIN of the natural person
  commonName: string | null;
  surname: string | null;
  givenName: string | null;
  organization: string | null;
  email: string | null;
  keyUsage: 'AUTH' | 'SIGN' | 'UNKNOWN';
  validFrom: Date;
  validTo: Date;
  serialNumberHex: string;
  certificatePem: string;
}

interface BackendOptions {
  backendUrl: string;             // base URL of your Kalkan signer service
  fetchInit?: RequestInit;        // headers, AbortSignal, etc.
}
```

Full TypeScript types ship with the package — `import type { ... } from '@smoker_winston/egov-helper'`.

---

## Limitations

- **`.p12` signing requires your own backend.** No third-party hosted signer exists for KZ keys; you have to run the Kalkan service yourself (it's a 1-line `docker compose up`).
- **`inspectSignature` only handles RSA CMS in the browser.** For GOST CMS verification, use the .NET package server-side.
- **eGov Mobile signing requires the user has eGov Mobile installed** and their cert is registered there. Most modern KZ users do.

---

## Versions

| Package | Latest | What's in it |
|---|---|---|
| `@smoker_winston/egov-helper` (npm) | 0.5.0 | + custom logo overlay on the QR (`logo: { src, size, … }`) + `overlayQrLogo` export |
| `@smoker_winston/egov-helper` | 0.4.0 | + `signDocumentViaQr` (eGov Mobile via SIGEX) |
| `@smoker_winston/egov-helper` | 0.3.0 | Backend-only signing; `backendUrl` required everywhere |
| `Tako0502.EgovHelper` (NuGet) | 0.1.1 | CMS verification, NUC RK CAs bundled |

---

## Development

```bash
git clone https://github.com/Tako0502/egov-helper
cd egov-helper
npm install
npm run build               # outputs dist/index.{js,cjs,d.ts} + dist/cli.mjs + dist/egov-helper.min.js
npm run typecheck           # strict
npm run test                # 27 RSA round-trip assertions

# Kalkan signer (Java)
cd packages/java/egov-helper-signer
./build.sh                  # installs Kalkan JARs into local maven repo + mvn package
java -jar target/egov-helper-signer.jar

# .NET package
cd packages/dotnet/EgovHelper.Net
dotnet build -c Release

# Tester UI
cd examples/vue
npm install && npm run dev  # http://localhost:5174
```

The full development workflow, troubleshooting, and operations checklist live in [`HOW-TO-USE.md`](HOW-TO-USE.md).

---

## License

MIT. See [`LICENSE`](LICENSE).

The Kalkan JAR (`knca_provider_jce_kalkan-*.jar`, `knca_provider_util-*.jar`) you drop into `packages/java/egov-helper-signer/libs/` is governed by NUC RK's own terms — don't redistribute it.
