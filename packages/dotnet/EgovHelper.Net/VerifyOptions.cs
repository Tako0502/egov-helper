using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Atasuai.EgovHelper;

/// <summary>
/// Options controlling how strictly <see cref="EgovSignatureVerifier.Verify(byte[], byte[], VerifyOptions)"/>
/// validates a signature.
/// </summary>
public sealed class VerifyOptions
{
    /// <summary>
    /// If true (default), the signer's certificate chain is built and validated. Without setting
    /// <see cref="TrustedRoots"/>, this validates against the OS's default trust store, which does
    /// NOT contain the NUC RK roots — so chain validation will typically fail. Either:
    ///   - set this to false and validate the chain yourself, or
    ///   - drop NUC RK root certificates into <see cref="TrustedRoots"/>.
    /// </summary>
    public bool ValidateCertificateChain { get; init; } = true;

    /// <summary>
    /// NUC RK root certificates (and any intermediates) the chain builder should trust.
    /// Use the bundled <see cref="EgovTrustRoots.Rsa"/> for the standard RSA flow:
    /// <code>TrustedRoots = EgovTrustRoots.Rsa.ToList()</code>
    /// or load your own from disk via <see cref="EgovTrustRoots.LoadFromDirectory"/>.
    /// </summary>
    public IList<X509Certificate2> TrustedRoots { get; init; } = new List<X509Certificate2>();

    /// <summary>
    /// If true, allow the verification to succeed even if the cert chain has a revocation status
    /// that's "Unknown" (offline). Useful behind air-gapped firewalls where CRL/OCSP can't be reached.
    /// Default: false.
    /// </summary>
    public bool IgnoreOfflineRevocation { get; init; }
}
