using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Tako0502.EgovHelper;

/// <summary>
/// Verifies CMS / CAdES-BES signatures produced by <c>@smoker_winston/egov-helper</c>'s
/// <c>signDocument()</c> (or by any other CMS producer — KalkanCrypt, NCALayer, etc.).
///
/// What this checks:
///   * The CMS parses cleanly.
///   * Each signer's signature value verifies against the embedded certificate.
///   * (Optionally) the certificate chain builds back to a trusted NUC RK root.
///   * The CAdES-BES <c>signingCertificateV2</c> attribute is present and binds the cert to the signature.
///   * Whether a CAdES-T timestamp token is embedded.
///
/// What this does NOT do:
///   * Verify revocation in real-time unless your trust store / OS provides CRL/OCSP for NUC RK.
///   * Authorize the signer for any business action — that's your code's job using the extracted BIN/IIN.
/// </summary>
public static class EgovSignatureVerifier
{
    // OIDs we care about.
    private const string SigningCertificateV2Oid = "1.2.840.113549.1.9.16.2.47";
    private const string SigningTimeOid = "1.2.840.113549.1.9.5";
    private const string TimeStampTokenOid = "1.2.840.113549.1.9.16.2.14";

    /// <summary>
    /// Verify a CMS signature. For detached signatures, pass the original <paramref name="document"/>.
    /// For attached signatures, leave it null — the embedded content is used.
    /// </summary>
    public static VerificationResult Verify(
        byte[] signature,
        byte[]? document = null,
        VerifyOptions? options = null)
    {
        if (signature is null || signature.Length == 0)
        {
            return new VerificationResult { ErrorMessage = "signature is empty" };
        }

        options ??= new VerifyOptions();

        SignedCms cms;
        try
        {
            if (document is null)
            {
                cms = new SignedCms();
                cms.Decode(signature);
            }
            else
            {
                cms = new SignedCms(new ContentInfo(document), detached: true);
                cms.Decode(signature);
            }
        }
        catch (CryptographicException ex)
        {
            return new VerificationResult { ErrorMessage = $"Could not decode CMS: {ex.Message}" };
        }

        var isAttached = document is null && cms.ContentInfo.Content is { Length: > 0 };
        var embeddedContent = isAttached ? cms.ContentInfo.Content : null;

        var signers = new List<SignerVerification>();
        var allValid = cms.SignerInfos.Count > 0;

        foreach (SignerInfo si in cms.SignerInfos)
        {
            var sv = BuildSignerVerification(si, options);
            signers.Add(sv);
            if (!sv.SignatureValid) allValid = false;
        }

        return new VerificationResult
        {
            Valid = allValid,
            IsAttached = isAttached,
            EmbeddedContent = embeddedContent,
            Signers = signers,
        };
    }

    /// <summary>
    /// Decode a CMS signature without doing any cryptographic verification — useful for displaying
    /// "who signed this and when" without taking on the cost of full validation.
    /// </summary>
    public static VerificationResult Inspect(byte[] signature)
    {
        return Verify(signature, document: null, options: new VerifyOptions
        {
            ValidateCertificateChain = false,
        });
    }

    // ────────────────────────────────────────────────────────────────────────

    private static SignerVerification BuildSignerVerification(SignerInfo si, VerifyOptions options)
    {
        var cert = si.Certificate;
        if (cert is null)
        {
            return new SignerVerification
            {
                CertInfo = null!,
                HashAlgorithm = FriendlyHash(si.DigestAlgorithm),
                SignatureValid = false,
                SignatureError = "Signer's certificate is not embedded in the CMS",
            };
        }

        var certInfo = BinExtractor.Extract(cert);
        var (signedAt, hasV2, hasTimestamp) = ReadAttributes(si);

        var signatureValid = false;
        string? signatureError = null;
        try
        {
            si.CheckSignature(verifySignatureOnly: !options.ValidateCertificateChain);

            if (options.ValidateCertificateChain)
            {
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                chain.ChainPolicy.VerificationFlags =
                    options.IgnoreOfflineRevocation
                        ? X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown
                          | X509VerificationFlags.IgnoreEndRevocationUnknown
                          | X509VerificationFlags.IgnoreRootRevocationUnknown
                        : X509VerificationFlags.NoFlag;

                foreach (var trusted in options.TrustedRoots)
                {
                    chain.ChainPolicy.ExtraStore.Add(trusted);
#if NET5_0_OR_GREATER
                    chain.ChainPolicy.CustomTrustStore.Add(trusted);
                    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
#endif
                }

                if (!chain.Build(cert))
                {
                    var chainErrors = string.Join(
                        ", ",
                        chain.ChainStatus.Select(s => s.StatusInformation.Trim()));
                    return new SignerVerification
                    {
                        CertInfo = certInfo,
                        SignedAt = signedAt,
                        HashAlgorithm = FriendlyHash(si.DigestAlgorithm),
                        HasSigningCertificateV2 = hasV2,
                        HasTimestamp = hasTimestamp,
                        SignatureValid = false,
                        SignatureError = $"Certificate chain did not build: {chainErrors}",
                    };
                }
            }

            signatureValid = true;
        }
        catch (CryptographicException ex)
        {
            signatureError = ex.Message;
        }

        return new SignerVerification
        {
            CertInfo = certInfo,
            SignedAt = signedAt,
            HashAlgorithm = FriendlyHash(si.DigestAlgorithm),
            HasSigningCertificateV2 = hasV2,
            HasTimestamp = hasTimestamp,
            SignatureValid = signatureValid,
            SignatureError = signatureError,
        };
    }

    private static (DateTime? signedAt, bool hasV2, bool hasTimestamp) ReadAttributes(SignerInfo si)
    {
        DateTime? signedAt = null;
        var hasV2 = false;
        var hasTimestamp = false;

        foreach (CryptographicAttributeObject attr in si.SignedAttributes)
        {
            if (attr.Oid.Value == SigningTimeOid)
            {
                foreach (var v in attr.Values.OfType<Pkcs9SigningTime>())
                {
                    signedAt = v.SigningTime;
                    break;
                }
            }
            else if (attr.Oid.Value == SigningCertificateV2Oid)
            {
                hasV2 = true;
            }
        }

        foreach (CryptographicAttributeObject attr in si.UnsignedAttributes)
        {
            if (attr.Oid.Value == TimeStampTokenOid)
            {
                hasTimestamp = true;
                break;
            }
        }

        return (signedAt, hasV2, hasTimestamp);
    }

    private static string FriendlyHash(Oid oid)
    {
        return oid.Value switch
        {
            "2.16.840.1.101.3.4.2.1" => "SHA-256",
            "2.16.840.1.101.3.4.2.2" => "SHA-384",
            "2.16.840.1.101.3.4.2.3" => "SHA-512",
            _ => oid.FriendlyName ?? oid.Value ?? "unknown",
        };
    }
}
