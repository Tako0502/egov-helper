// Cross-language validation: read CMS signatures produced by the JS side
// (scripts/smoke-test.mjs writes them to tmp/) and verify them with this package.
// This proves the JS CAdES-BES output is consumable by .NET's standard SignedCms.
//
// Run from repo root:
//   npm run test                                    # produces tmp/* artifacts
//   dotnet run --project packages/dotnet/EgovHelper.Net.Tests

using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using Tako0502.EgovHelper;

var repoRoot = FindRepoRoot();
var tmp = Path.Combine(repoRoot, "tmp");
Console.WriteLine($"== egov-helper cross-validation ==");
Console.WriteLine($"reading artifacts from {tmp}\n");

if (!Directory.Exists(tmp) || !File.Exists(Path.Combine(tmp, "expected.json")))
{
    Console.Error.WriteLine("tmp/ artifacts missing. Run `npm run test` first.");
    return 2;
}

var passed = 0;
var failed = 0;

void Expect(string name, bool ok, string? detail = null)
{
    if (ok)
    {
        Console.WriteLine($"  ok   {name}");
        passed++;
    }
    else
    {
        Console.WriteLine($"  FAIL {name}{(detail is null ? "" : $"\n       {detail}")}");
        failed++;
    }
}

var expectedJson = File.ReadAllText(Path.Combine(tmp, "expected.json"));
var expected = JsonSerializer.Deserialize<JsonElement>(expectedJson);
var expectedBin = expected.GetProperty("bin").GetString();
var expectedIin = expected.GetProperty("iin").GetString();
var expectedCn = expected.GetProperty("commonName").GetString();

var doc = File.ReadAllBytes(Path.Combine(tmp, "doc.bin"));
var sigDetached = File.ReadAllBytes(Path.Combine(tmp, "sig-detached.cms"));
var sigAttached = File.ReadAllBytes(Path.Combine(tmp, "sig-attached.cms"));

Console.WriteLine("1. Verify the detached signature");
{
    // Skip chain validation: the JS test uses a self-signed cert that's not trusted by the OS.
    var r = EgovSignatureVerifier.Verify(sigDetached, doc, new VerifyOptions
    {
        ValidateCertificateChain = false,
    });
    Expect("CMS decoded with no top-level error", r.ErrorMessage is null, r.ErrorMessage);
    Expect("Valid = true", r.Valid);
    Expect("IsAttached = false", !r.IsAttached);
    Expect("Exactly one signer", r.Signers.Count == 1);

    if (r.Signers.Count == 1)
    {
        var s = r.Signers[0];
        Expect("Signer signature value verifies", s.SignatureValid, s.SignatureError);
        Expect("Hash algorithm = SHA-256", s.HashAlgorithm == "SHA-256", $"got {s.HashAlgorithm}");
        Expect("CAdES-BES (signingCertificateV2) detected", s.HasSigningCertificateV2);
        Expect($"Cert BIN matches ({expectedBin})", s.CertInfo.Bin == expectedBin, $"got {s.CertInfo.Bin ?? "(null)"}");
        Expect($"Cert IIN matches ({expectedIin})", s.CertInfo.Iin == expectedIin, $"got {s.CertInfo.Iin ?? "(null)"}");
        Expect($"Cert CN matches ({expectedCn})", s.CertInfo.CommonName == expectedCn, $"got {s.CertInfo.CommonName ?? "(null)"}");
        Expect("SignedAt is set", s.SignedAt.HasValue);
    }
}

Console.WriteLine("\n2. Verify the attached signature (no document supplied)");
{
    var r = EgovSignatureVerifier.Verify(sigAttached, document: null, new VerifyOptions
    {
        ValidateCertificateChain = false,
    });
    Expect("Valid = true", r.Valid, r.Signers.FirstOrDefault()?.SignatureError);
    Expect("IsAttached = true", r.IsAttached);
    Expect("EmbeddedContent matches original", r.EmbeddedContent != null && r.EmbeddedContent.SequenceEqual(doc));
}

Console.WriteLine("\n3. Inspect (no verification)");
{
    var r = EgovSignatureVerifier.Inspect(sigDetached);
    Expect("Inspect returns one signer", r.Signers.Count == 1);
    if (r.Signers.Count == 1)
    {
        var s = r.Signers[0];
        Expect("BIN extracted via Inspect", s.CertInfo.Bin == expectedBin);
    }
}

Console.WriteLine("\n4. Detached signature with WRONG document → must fail");
{
    var wrongDoc = System.Text.Encoding.UTF8.GetBytes("a different contract");
    var r = EgovSignatureVerifier.Verify(sigDetached, wrongDoc, new VerifyOptions
    {
        ValidateCertificateChain = false,
    });
    Expect("Valid = false on wrong document", !r.Valid);
}

Console.WriteLine("\n5. EgovTrustRoots — bundled NUC RK CAs");
{
    var rsa = EgovTrustRoots.Rsa;
    var gost = EgovTrustRoots.Gost;
    var all = EgovTrustRoots.All;

    Expect("Rsa returns 2 certs", rsa.Count == 2, $"got {rsa.Count}");
    Expect("Gost returns 2 certs", gost.Count == 2, $"got {gost.Count}");
    Expect("All returns 4 certs", all.Count == 4, $"got {all.Count}");

    // The root_rsa_2020 cert should self-sign — subject == issuer.
    var rootRsa = rsa.FirstOrDefault(c => c.Subject.Contains("RSA") && !c.Subject.Contains("2022"));
    Expect("root_rsa_2020 is self-signed", rootRsa != null && rootRsa.Subject == rootRsa.Issuer);

    // The nca_rsa_2022 should be issued BY the root_rsa_2020.
    var ncaRsa = rsa.FirstOrDefault(c => c.Subject.Contains("RSA") && c.Subject.Contains("2022"));
    Expect("nca_rsa_2022 is issued by root_rsa_2020", ncaRsa != null && rootRsa != null && ncaRsa.Issuer == rootRsa.Subject);

    // Repeat call should not reload from the assembly each time — same instances.
    Expect("Rsa is cached (same instances on second call)", ReferenceEquals(EgovTrustRoots.Rsa[0], rsa[0]));
}

Console.WriteLine($"\n{passed} passed, {failed} failed");
return failed > 0 ? 1 : 0;

static string FindRepoRoot()
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "package.json")))
    {
        dir = dir.Parent;
    }
    return dir?.FullName ?? throw new InvalidOperationException("Could not locate repo root (no package.json found in any parent)");
}
