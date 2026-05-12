// Drop this into your existing AtasuSite / AtasuWeb / similar Controllers folder.
// Requires:
//   dotnet add package Tako0502.EgovHelper
//
// Two endpoints:
//   GET  /Contract/Sign         → renders Sign.cshtml (the form)
//   POST /Contract/Sign         → receives the CMS, verifies it, stores the signed contract

using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Tako0502.EgovHelper;

namespace AtasuWeb.Controllers;

public class ContractController : Controller
{
    // Held once at app start. NUC RK root + intermediate CAs come bundled inside the
    // Tako0502.EgovHelper NuGet — no manual download.
    private static readonly VerifyOptions _verifyOpts = new()
    {
        ValidateCertificateChain = true,
        TrustedRoots = EgovTrustRoots.Rsa.Concat(EgovTrustRoots.Gost).ToList(),
        IgnoreOfflineRevocation = true, // set false if your env reliably reaches NUC RK CRL/OCSP
    };

    // GET /Contract/Sign — render the form. The view loads the JS bundle and exercises
    // window.EgovHelper.signDocument(...) entirely client-side.
    [HttpGet]
    public IActionResult Sign(int id)
    {
        ViewBag.ContractId = id;
        ViewBag.ContractText = LoadContractText(id);   // your data source
        ViewBag.BackendUrl   = "http://localhost:7676"; // base URL of the Kalkan signer
        return View();
    }

    // POST /Contract/Sign — verify the signature the browser produced and store it.
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Sign([FromBody] SignedContractDto req)
    {
        if (string.IsNullOrWhiteSpace(req.SignatureBase64))
            return BadRequest(new { error = "signatureBase64 is required" });

        byte[] signature;
        try { signature = Convert.FromBase64String(req.SignatureBase64); }
        catch { return BadRequest(new { error = "signatureBase64 is not valid base64" }); }

        var documentText = LoadContractText(req.ContractId);
        var documentBytes = System.Text.Encoding.UTF8.GetBytes(documentText);

        // Verify the CMS against the document, the NUC RK trust chain, and the cert
        // we expect (BIN match).
        var result = EgovSignatureVerifier.Verify(signature, documentBytes, _verifyOpts);
        if (!result.Valid)
        {
            return BadRequest(new
            {
                error = result.ErrorMessage ?? result.Signers.FirstOrDefault()?.SignatureError ?? "verification failed",
            });
        }

        var signer = result.Signers[0];

        // Defense in depth: confirm the user signed with the BIN they told us they owned.
        if (req.ExpectedBin is not null && signer.CertInfo.Bin != req.ExpectedBin)
        {
            return StatusCode(403, new { error = $"Cert BIN {signer.CertInfo.Bin} does not match the user's claim {req.ExpectedBin}" });
        }

        SaveSignedContract(new SignedContractRecord
        {
            ContractId    = req.ContractId,
            SignerName    = signer.CertInfo.CommonName ?? "(unknown)",
            SignerBin     = signer.CertInfo.Bin,
            SignerIin     = signer.CertInfo.Iin,
            SignedAtUtc   = signer.SignedAt ?? DateTime.UtcNow,
            CmsBlob       = signature,
            CadesBes      = signer.HasSigningCertificateV2,
            CadesT        = signer.HasTimestamp,
        });

        return Ok(new
        {
            signer    = signer.CertInfo.CommonName,
            bin       = signer.CertInfo.Bin,
            iin       = signer.CertInfo.Iin,
            signedAt  = signer.SignedAt,
            algorithm = signer.HashAlgorithm,
        });
    }

    // ─── Replace these with your real data layer ────────────────────────────

    private string LoadContractText(int id)
    {
        // Pull from your DB / file system / wherever your contract text lives.
        return $"Contract #{id} — terms go here. The exact bytes signed must equal these bytes.";
    }

    private void SaveSignedContract(SignedContractRecord record)
    {
        // Persist to MySQL / SQL Server / wherever. Keep the CmsBlob as bytea/varbinary.
    }
}

public class SignedContractDto
{
    public int ContractId { get; set; }
    public string SignatureBase64 { get; set; } = string.Empty;
    /// <summary>The BIN the user typed in the form, for defence-in-depth comparison.</summary>
    public string? ExpectedBin { get; set; }
}

public class SignedContractRecord
{
    public int ContractId { get; set; }
    public string SignerName { get; set; } = string.Empty;
    public string? SignerBin { get; set; }
    public string? SignerIin { get; set; }
    public DateTime SignedAtUtc { get; set; }
    public byte[] CmsBlob { get; set; } = Array.Empty<byte>();
    public bool CadesBes { get; set; }
    public bool CadesT { get; set; }
}
