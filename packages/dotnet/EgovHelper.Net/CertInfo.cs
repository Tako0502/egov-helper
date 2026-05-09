using System;
using System.Security.Cryptography.X509Certificates;

namespace Atasuai.EgovHelper;

/// <summary>
/// High-level summary of a NUC RK X.509 certificate. Equivalent to the
/// <c>CertInfo</c> type exported from the <c>@atasuai/egov-helper</c> JS package.
/// </summary>
public sealed class CertInfo
{
    /// <summary>12-digit BIN of the legal entity, or null if not present in the cert subject.</summary>
    public string? Bin { get; init; }

    /// <summary>12-digit IIN of the natural person, or null.</summary>
    public string? Iin { get; init; }

    /// <summary>Common Name (CN) — usually the owner's full name.</summary>
    public string? CommonName { get; init; }

    /// <summary>Surname (SN).</summary>
    public string? Surname { get; init; }

    /// <summary>Given name (GN).</summary>
    public string? GivenName { get; init; }

    /// <summary>Organization (O) — present on legal-entity certs.</summary>
    public string? Organization { get; init; }

    /// <summary>Email address embedded in the subject, if any.</summary>
    public string? Email { get; init; }

    /// <summary>Certificate validity start.</summary>
    public DateTime ValidFrom { get; init; }

    /// <summary>Certificate validity end.</summary>
    public DateTime ValidTo { get; init; }

    /// <summary>Hex string of the certificate's own serial number.</summary>
    public string SerialNumberHex { get; init; } = string.Empty;

    /// <summary>The underlying certificate, in case the caller needs lower-level access.</summary>
    public X509Certificate2 Certificate { get; init; } = null!;
}
