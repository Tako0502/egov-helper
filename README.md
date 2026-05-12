# egov-helper

Helper library for Kazakhstan e-Gov digital signatures, **without NCALayer**.

The user picks their NUC RK `.p12` (`.pfx`) file in your form. This library:

1. **Verifies** the BIN/IIN they typed matches the BIN/IIN in their certificate.
2. **Signs** documents with their key, producing a CAdES-BES (RFC 5126) CMS / PKCS#7 SignedData blob.
3. **Decodes** any CMS signature — yours or someone else's — into readable fields (signer cert, BIN/IIN, signed time, hash algorithm, attached/detached, signature validity, timestamp presence).
4. **Timestamps** an existing signature by round-tripping through an RFC 3161 TSA (CAdES-T).
5. **Verifies on the backend** via the companion .NET package `Tako0502.EgovHelper`.

The private key from a `.p12` file never leaves the JS runtime that calls these functions.

---

## Two packages

| Package | Where it runs | What it's for |
|---|---|---|
| `@smoker_winston/egov-helper` (this repo, npm) | browser + Node | sign, inspect, timestamp, BIN/IIN check |
| `Tako0502.EgovHelper` (`packages/dotnet/`, NuGet) | any .NET 6/8/9/10 backend | verify signatures, validate cert chain against NUC RK roots |

Each project picks whichever side it needs. iOS / Android can hit the .NET backend over HTTP — they don't need a native helper for the verification half.

---

## Install

### JS / TS (Vue, React, Node, Razor frontend)

```bash
npm install @smoker_winston/egov-helper
```

```ts
import { checkBin, signDocument, inspectSignature, addTimestamp } from '@smoker_winston/egov-helper';
```

### Single `<script>` for Razor / MVC views

Either pull from a CDN:

```html
<script src="https://unpkg.com/@smoker_winston/egov-helper/dist/egov-helper.min.js"></script>
<script>
  const { checkBin, signDocument, inspectSignature } = window.EgovHelper;
</script>
```

…or `npm install` and copy `node_modules/@smoker_winston/egov-helper/dist/egov-helper.min.js` into your project's static folder so it ships with your build.

### .NET backend

```bash
dotnet add package Tako0502.EgovHelper
```

```csharp
using Tako0502.EgovHelper;
var result = EgovSignatureVerifier.Verify(signatureBytes, documentBytes);
```

---

## Usage

### 1. `checkBin(p12, password, typedBin) → CheckBinResult`

```ts
const fileInput = document.querySelector('input[type=file]');
const result = await checkBin(fileInput.files[0], passwordField.value, '123456789012');

if (!result.match) {
  alert(`Key does not match BIN ${typedBin}.\nCert BIN: ${result.certBin}\nCert IIN: ${result.certIin}`);
  return;
}
console.log('Owner:', result.certInfo.commonName, '— valid until', result.certInfo.validTo);
```

`checkBin` strips non-digit characters from the typed value, so users can paste BINs in any format. It checks against **both** the cert's BIN and IIN and tells you which one matched (or `null` if neither).

### 2. `signDocument(p12, password, content, options?) → SignResult`

Produces a **CAdES-BES** signature: standard CMS / PKCS#7 SignedData with the mandatory `signingCertificateV2` (RFC 5035 / ESS) attribute that binds the signing certificate's hash into the signature.

```ts
const docBytes = new Uint8Array(await contractFile.arrayBuffer());
const sig = await signDocument(p12File, password, docBytes); // detached, SHA-256

// Send to your backend for verification + storage:
await fetch('/api/contracts/sign', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    contractId: 'C-12345',
    signatureBase64: sig.signatureBase64,
    signedAt: sig.signedAt.toISOString(),
    signerBin: sig.certInfo.bin,
    signerIin: sig.certInfo.iin,
  }),
});
```

Options:

```ts
await signDocument(p12, pass, doc, {
  detached: false,         // default: true. false = embed the document in the signature
  hashAlgorithm: 'SHA-384',// default: 'SHA-256'. Also: 'SHA-512'

  // Transport selection (v0.2.0+)
  transport: 'auto',       // 'browser' | 'backend' | 'auto' (default)
  backendSignUrl: 'https://signer.example.kz/sign',  // required for GOST
});
```

**Transport options** (new in 0.2.0):

| `transport` | What it does | Works for |
|---|---|---|
| `'browser'` | Signs in-browser with node-forge. Private key never leaves the user's browser. | **RSA only.** Throws `GOST not supported` on GOST keys. |
| `'backend'` | POSTs the `.p12`, password, and document to `backendSignUrl`. Your server signs with Kalkan (Java). | RSA + GOST. Key transits to backend over TLS. |
| `'auto'` (default) | Tries browser first. If the key is GOST and `backendSignUrl` is set, falls back to backend automatically. | Both — RSA stays in-browser, GOST routes to backend. |

For the `'backend'` path, you need to run [`packages/java/egov-helper-signer/`](packages/java/egov-helper-signer/) — a Javalin service that wraps NUC RK's KalkanCrypt JCE provider. See its README for setup (requires applying for the Kalkan SDK at <https://sdk.pki.gov.kz/>).

For local development without Kalkan, [`scripts/mock-backend.mjs`](scripts/mock-backend.mjs) is a Node.js stand-in that implements the same wire protocol using the in-browser signer (RSA only — proves the transport works, but doesn't unlock GOST).

### 3. `inspectSignature(input, options?) → SignatureInspection`

Decode a CMS signature blob — yours or someone else's — and read everything inside it.

Accepts: base64 string, hex string, `Uint8Array`, or `ArrayBuffer`.

```ts
const info = await inspectSignature(signatureBase64, { document: docBytes });

console.log('Signed by:', info.signers[0].certInfo.commonName);
console.log('BIN:', info.signers[0].certInfo.bin);
console.log('IIN:', info.signers[0].certInfo.iin);
console.log('Signed at:', info.signers[0].signedAt);
console.log('Hash:', info.signers[0].hashAlgorithm);
console.log('Detached:', !info.attached);
console.log('CAdES-BES (V2 attr):', info.signers[0].hasSigningCertificateV2);
console.log('CAdES-T (timestamp):', info.hasTimestamp, info.timestampAt);
console.log('Signature value verifies vs embedded cert:', info.signers[0].signatureValid);
console.log('Document digest matches:', info.documentDigestMatches);
```

The `documentDigestMatches` field is `null` unless you pass `options.document`. Use it to detect tampering: if it's `false`, someone altered the document after it was signed.

`signatureValid` is local-only — it proves the signed attributes weren't tampered with by anyone who doesn't hold the private key. It does **not** prove the certificate is trusted (chain validation against NUC RK roots — do that on your backend with the .NET package).

### 4. `addTimestamp(signature, { tsaUrl }) → Uint8Array`

Upgrade a CAdES-BES signature to **CAdES-T** by round-tripping through an RFC 3161 Time Stamping Authority. The TimeStampToken is embedded as an unsigned attribute on the SignerInfo.

```ts
import { addTimestamp } from '@smoker_winston/egov-helper';

const cmsT = await addTimestamp(sig.signature, {
  tsaUrl: 'https://tsp.pki.gov.kz/tsp',  // KZ TSA
});
```

> **CORS warning**: public TSAs (including KZ's) do not return CORS headers, so this call **fails from a browser**. Run it from your backend (Node 18+ has `fetch` natively), or stand up a thin proxy endpoint your frontend can call.

### 5. Backend verification (.NET)

```csharp
using Tako0502.EgovHelper;
using System.Linq;

[HttpPost("/api/contracts/sign")]
public IActionResult Sign([FromBody] SignRequest req)
{
    var signature = Convert.FromBase64String(req.SignatureBase64);
    var document  = Encoding.UTF8.GetBytes(req.ContractText);

    // The NUC RK root + intermediate CAs are bundled inside the package — no need
    // to download or distribute them yourself. (They're public infrastructure;
    // refresh with scripts/fetch-nuc-roots.sh if pki.gov.kz publishes new ones.)
    var result = EgovSignatureVerifier.Verify(signature, document, new VerifyOptions
    {
        ValidateCertificateChain = true,
        TrustedRoots             = EgovTrustRoots.Rsa.ToList(),
    });

    if (!result.Valid)
    {
        return BadRequest(new { error = result.Signers.FirstOrDefault()?.SignatureError });
    }

    var signer = result.Signers[0];
    if (signer.CertInfo.Bin != req.ExpectedBin)
    {
        return Forbid("Signing cert BIN does not match the user's claimed BIN");
    }

    return Ok(new {
        signer    = signer.CertInfo.CommonName,
        bin       = signer.CertInfo.Bin,
        signedAt  = signer.SignedAt,
        cadesBes  = signer.HasSigningCertificateV2,
        timestamp = signer.HasTimestamp,
    });
}
```

See [`packages/dotnet/EgovHelper.Net/README.md`](packages/dotnet/EgovHelper.Net/README.md) for the full .NET API.

---

## API summary

### JS

| Function | Returns |
|---|---|
| `checkBin(p12, password, typedBin)` | `Promise<CheckBinResult>` |
| `signDocument(p12, password, content, options?)` | `Promise<SignResult>` |
| `inspectSignature(input, options?)` | `Promise<SignatureInspection>` |
| `addTimestamp(signature, options)` | `Promise<Uint8Array>` |
| `parseP12(p12, password)` | `Promise<ParsedP12>` *(low-level — gives you the raw forge cert + key)* |
| `extractCertInfo(cert)` | `CertInfo` *(low-level — takes a forge `Certificate`)* |

Full TypeScript types are shipped in `dist/index.d.ts`.

### .NET

| Method | Returns |
|---|---|
| `EgovSignatureVerifier.Verify(signature, document?, options?)` | `VerificationResult` |
| `EgovSignatureVerifier.Inspect(signature)` | `VerificationResult` (no chain validation) |
| `BinExtractor.Extract(cert)` | `CertInfo` |

---

## Build, test, develop

```bash
npm install
npm run typecheck            # strict TS check
npm run build                # outputs dist/index.{js,cjs,d.ts} + dist/egov-helper.min.js
npm run test                 # build + Node smoke test (27 assertions on sign/inspect/check round-trips)
npm run demo                 # build + serve plain-HTML demo on http://localhost:5173

# Cross-language validation: .NET reads JS-produced signatures and verifies them
npm run test                                                    # produces tmp/* artifacts
dotnet run --project packages/dotnet/EgovHelper.Net.Tests       # 23 assertions, incl. EgovTrustRoots

# Build the .NET package
dotnet build -c Release packages/dotnet/EgovHelper.Net

# Refresh the bundled NUC RK CA certificates (only needed if pki.gov.kz rotates them)
scripts/fetch-nuc-roots.sh

# Vue 3 example
cd examples/vue && npm install && npm run dev    # http://localhost:5174
```

### Validate against a real NUC RK key

The 27-assertion smoke test uses a synthetic self-signed cert. To prove the round-trip
works against an actual `.p12` issued by egov.kz, run:

```bash
node scripts/test-with-real-p12.mjs ~/Downloads/AUTH_RSA256_xxxx.p12 'YourPassword' 123456789012
dotnet run --project packages/dotnet/EgovHelper.Net.Tests
```

Both pass → JS-produced CMS is verifiable by .NET, BIN/IIN extraction works on real subjects,
and CAdES-BES is structurally correct. Your `.p12` and password never leave your machine.

---

## Limitations

- **GOST keys are not supported.** A small fraction of older NUC RK `.p12` files use GOST R 34.10-2001 / 34.10-2012. Detected automatically — `parseP12` throws a clear error pointing the user at egov.kz to reissue an RSA cert (free, takes ~1 minute) or NCALayer for that user.
- **TSA timestamping must run server-side** unless your TSA endpoint returns CORS headers (public ones don't).
- **CAdES-BES, not CAdES-LT/LTA**. No long-term validation material (CRLs / OCSP responses embedded). Add by extending `signDocument` if you need archival signatures.

---

## License

MIT
