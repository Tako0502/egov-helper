using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace Tako0502.EgovHelper;

/// <summary>
/// Pulls a high-level <see cref="CertInfo"/> out of a NUC RK X.509 certificate.
///
/// KZ certificates put the BIN/IIN in either the SERIALNUMBER (OID 2.5.4.5) or the OU
/// (OID 2.5.4.11) attribute of the subject, formatted as e.g. "IIN123456789012" or
/// "BIN123456789012". This class knows about both shapes.
/// </summary>
public static class BinExtractor
{
    /// <summary>
    /// Extract a high-level <see cref="CertInfo"/> (BIN, IIN, CN, organization, validity)
    /// from a NUC RK X.509 certificate.
    /// </summary>
    public static CertInfo Extract(X509Certificate2 cert)
    {
        var attrs = ParseDistinguishedName(cert.Subject);

        var serialNumber = TryGet(attrs, "SERIALNUMBER", "OID.2.5.4.5", "2.5.4.5") ?? string.Empty;
        var ou = TryGet(attrs, "OU", "OID.2.5.4.11", "2.5.4.11") ?? string.Empty;

        var iin = MatchKzId(serialNumber, "IIN") ?? MatchKzId(ou, "IIN");
        var bin = MatchKzId(serialNumber, "BIN") ?? MatchKzId(ou, "BIN");

        return new CertInfo
        {
            Bin = bin,
            Iin = iin,
            CommonName = TryGet(attrs, "CN"),
            Surname = TryGet(attrs, "SN", "SURNAME"),
            GivenName = TryGet(attrs, "G", "GN", "GIVENNAME"),
            Organization = TryGet(attrs, "O"),
            Email = TryGet(attrs, "E", "EMAIL", "EMAILADDRESS"),
            ValidFrom = cert.NotBefore,
            ValidTo = cert.NotAfter,
            SerialNumberHex = cert.SerialNumber,
            Certificate = cert,
        };
    }

    private static readonly Regex SubjectSplitter = new(
        @",\s*(?=[A-Za-z0-9.]+\s*=)",
        RegexOptions.Compiled);

    private static IDictionary<string, string> ParseDistinguishedName(string subject)
    {
        // .NET's cert.Subject is a comma-separated list of "KEY=VALUE" pairs.
        // KZ NUC subjects don't use escaped commas inside values, so a simple split is fine.
        var result = new Dictionary<string, string>(System.StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(subject)) return result;

        var parts = SubjectSplitter.Split(subject);
        foreach (var part in parts)
        {
            var eq = part.IndexOf('=');
            if (eq <= 0) continue;
            var key = part.Substring(0, eq).Trim();
            var value = part.Substring(eq + 1).Trim();
            // Strip surrounding quotes if present.
            if (value.Length >= 2 && value[0] == '"' && value[^1] == '"')
            {
                value = value.Substring(1, value.Length - 2);
            }
            if (!result.ContainsKey(key)) result[key] = value;
        }
        return result;
    }

    private static string? TryGet(IDictionary<string, string> attrs, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (attrs.TryGetValue(key, out var v) && !string.IsNullOrEmpty(v)) return v;
        }
        return null;
    }

    private static string? MatchKzId(string value, string prefix)
    {
        if (string.IsNullOrEmpty(value)) return null;
        var m = Regex.Match(value, $@"{prefix}[\s:=]*?(\d{{12}})", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value : null;
    }
}
