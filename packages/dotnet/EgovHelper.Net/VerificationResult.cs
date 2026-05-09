using System;
using System.Collections.Generic;

namespace Atasuai.EgovHelper;

/// <summary>
/// Outcome of <see cref="EgovSignatureVerifier.Verify(byte[], byte[], VerifyOptions)"/>.
/// </summary>
public sealed class VerificationResult
{
    /// <summary>True if every signer's signature checked out (and, when ValidateCertificateChain is on, every chain too).</summary>
    public bool Valid { get; init; }

    /// <summary>True if the document content was embedded inside the CMS (attached); false if detached.</summary>
    public bool IsAttached { get; init; }

    /// <summary>If you supplied <c>document</c> but the signature is attached, this contains the embedded copy.</summary>
    public byte[]? EmbeddedContent { get; init; }

    /// <summary>Per-signer details — there's almost always exactly one.</summary>
    public IReadOnlyList<SignerVerification> Signers { get; init; } = Array.Empty<SignerVerification>();

    /// <summary>Top-level error, if any (parse failure, malformed CMS, etc.).</summary>
    public string? ErrorMessage { get; init; }
}

/// <summary>
/// Per-signer details inside a <see cref="VerificationResult"/>.
/// CMS allows multiple signers; in NUC RK practice there's usually exactly one.
/// </summary>
public sealed class SignerVerification
{
    /// <summary>BIN/IIN/CN/etc. extracted from the signer's certificate.</summary>
    public CertInfo CertInfo { get; init; } = null!;

    /// <summary>Time recorded in the signingTime authenticated attribute, if present.</summary>
    public DateTime? SignedAt { get; init; }

    /// <summary>Hash algorithm name (e.g. "SHA-256") declared in the SignerInfo.</summary>
    public string HashAlgorithm { get; init; } = string.Empty;

    /// <summary>True if the CAdES-BES <c>signingCertificateV2</c> (RFC 5035 / ESS) attribute is present.</summary>
    public bool HasSigningCertificateV2 { get; init; }

    /// <summary>True if the CMS includes a TimeStampToken in unsigned attributes (CAdES-T).</summary>
    public bool HasTimestamp { get; init; }

    /// <summary>True if this signer's RSA signature value verifies against the embedded certificate's public key.</summary>
    public bool SignatureValid { get; init; }

    /// <summary>If <see cref="SignatureValid"/> is false, the underlying error message.</summary>
    public string? SignatureError { get; init; }
}
