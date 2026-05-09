# Tako0502.EgovHelper

Backend companion for [`@smoker_winston/egov-helper`](https://www.npmjs.com/package/@smoker_winston/egov-helper).

Verifies CMS / CAdES-BES signatures produced by Kazakhstan e-Gov certificates (NUC RK / pki.gov.kz) and extracts BIN/IIN/owner info from the signing certificate. **No NCALayer required on the server side** — pure .NET, uses `System.Security.Cryptography.Pkcs.SignedCms`.

## Install

```bash
dotnet add package Tako0502.EgovHelper
```

Targets `netstandard2.1` and `net8.0`.

## Usage

### Verify a signature posted from your frontend

The browser uses `@smoker_winston/egov-helper` to sign a contract and POSTs you the base64 signature (and, for detached signatures, the original document):

```csharp
using Tako0502.EgovHelper;
using System.Security.Cryptography.X509Certificates;

[HttpPost("/api/contracts/sign")]
public IActionResult Sign([FromBody] SignRequest req)
{
    var signature = Convert.FromBase64String(req.SignatureBase64);
    var document = Encoding.UTF8.GetBytes(req.ContractText);

    // Load NUC RK roots once at app startup, not on every request.
    var roots = new[]
    {
        new X509Certificate2("certs/root_rsa.cer"),
        new X509Certificate2("certs/nca_rsa.cer"),
    };

    var result = EgovSignatureVerifier.Verify(signature, document, new VerifyOptions
    {
        ValidateCertificateChain = true,
        TrustedRoots = roots,
        IgnoreOfflineRevocation = false,
    });

    if (!result.Valid)
    {
        return BadRequest(new
        {
            error = result.ErrorMessage ?? result.Signers.FirstOrDefault()?.SignatureError,
        });
    }

    var signer = result.Signers[0];

    // The whole point of this library: prove that whoever signed the contract really
    // owns this BIN/IIN, not just that they typed it in your form.
    if (signer.CertInfo.Bin != req.ExpectedBin)
    {
        return Forbid("Signing cert BIN does not match the user's claimed BIN");
    }

    return Ok(new
    {
        signer = signer.CertInfo.CommonName,
        bin = signer.CertInfo.Bin,
        iin = signer.CertInfo.Iin,
        signedAt = signer.SignedAt,
        cadesBes = signer.HasSigningCertificateV2,
        timestamped = signer.HasTimestamp,
    });
}
```

### Just decode (no verification — for showing "who signed this")

```csharp
var result = EgovSignatureVerifier.Inspect(signatureBytes);
foreach (var s in result.Signers)
{
    Console.WriteLine($"Signed by {s.CertInfo.CommonName} (BIN: {s.CertInfo.Bin}) at {s.SignedAt}");
}
```

### Extract BIN/IIN from a certificate you already have

```csharp
var cert = new X509Certificate2("user.cer");
var info = BinExtractor.Extract(cert);
Console.WriteLine($"BIN: {info.Bin}, IIN: {info.Iin}");
```

## Trust setup — getting NUC RK roots

`SignedCms.CheckSignature(verifySignatureOnly: false)` only validates against trust roots installed on the OS, which on Windows / Linux / macOS does **not** include NUC RK by default. You have two options:

1. **Pass roots explicitly** (recommended): download from <https://pki.gov.kz/> and pass via `VerifyOptions.TrustedRoots`. On .NET 5+ this uses `X509ChainTrustMode.CustomRootTrust`, so the OS store is bypassed entirely. On netstandard2.1 the roots go into `ExtraStore` and you need them installed in the OS trust store too.
2. **Skip chain validation** (`ValidateCertificateChain = false`): only checks that the signature value verifies against the embedded cert. Acceptable if you trust the cert by other means (e.g. you imported it from a recent successful login).

## What's verified

| Check | `Inspect()` | `Verify(opts.ValidateCertificateChain=false)` | `Verify(opts.ValidateCertificateChain=true)` |
|---|---|---|---|
| CMS parses | ✅ | ✅ | ✅ |
| Signed attributes extracted | ✅ | ✅ | ✅ |
| Cert chain built | – | – | ✅ |
| Signer's RSA signature checks against cert | – | ✅ | ✅ |
| Cert revocation (CRL/OCSP) | – | – | ✅ (best-effort, see `IgnoreOfflineRevocation`) |
| `messageDigest` matches the document | implicit (CheckSignature does this when document is provided) | ✅ | ✅ |
| Timestamp token (CAdES-T) authenticity | flagged but not verified | flagged but not verified | flagged but not verified |

## License

MIT
