using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace Atasuai.EgovHelper;

/// <summary>
/// Trust anchors for NUC RK signature verification.
///
/// The OS trust store on Windows / Linux / macOS does NOT include NUC RK roots,
/// so by default <see cref="X509Chain.Build"/> rejects any certificate signed by them.
/// This class ships the public root + intermediate CAs so callers can verify chains out
/// of the box without manually downloading anything.
///
/// Source: <see href="https://pki.gov.kz/cert/"/>. The bundled bytes are the canonical
/// public certificates — no secrets here. Refresh with <c>scripts/fetch-nuc-roots.sh</c>
/// if NUC RK publishes new ones.
/// </summary>
public static class EgovTrustRoots
{
    /// <summary>
    /// All four bundled NUC RK CA certificates (root + intermediate, RSA + GOST).
    /// Pass directly to <see cref="VerifyOptions.TrustedRoots"/>.
    /// </summary>
    public static IReadOnlyList<X509Certificate2> All => GetCached(_all);

    /// <summary>
    /// RSA-only chain (root_rsa_2020 + nca_rsa_2022). This is what you want for the
    /// signature flow @atasuai/egov-helper produces, since it's RSA-only.
    /// </summary>
    public static IReadOnlyList<X509Certificate2> Rsa => GetCached(_rsa);

    /// <summary>
    /// GOST-only chain (root_gost_2022 + nca_gost_2022). Useful only if you're verifying
    /// signatures produced by GOST keys via a different toolchain (KalkanCrypt, NCALayer).
    /// This library cannot itself produce or verify GOST signatures.
    /// </summary>
    public static IReadOnlyList<X509Certificate2> Gost => GetCached(_gost);

    /// <summary>
    /// Convenience: load every <c>.cer</c> / <c>.crt</c> / <c>.pem</c> / <c>.der</c>
    /// file in <paramref name="directory"/> as <see cref="X509Certificate2"/>.
    /// Use this if you've placed your own trust roots on disk (e.g. via the bundled
    /// <c>scripts/fetch-nuc-roots.sh</c>).
    /// </summary>
    public static IReadOnlyList<X509Certificate2> LoadFromDirectory(string directory)
    {
        if (string.IsNullOrEmpty(directory))
            throw new ArgumentException("directory must be non-empty", nameof(directory));
        if (!Directory.Exists(directory))
            throw new DirectoryNotFoundException($"trust roots directory not found: {directory}");

        var extensions = new[] { ".cer", ".crt", ".pem", ".der" };
        var files = Directory
            .EnumerateFiles(directory)
            .Where(f => extensions.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase))
            .ToList();

        var certs = new List<X509Certificate2>(files.Count);
        foreach (var path in files)
        {
            certs.Add(new X509Certificate2(path));
        }
        return certs;
    }

    // ────────────────────────────────────────────────────────────────────────

    private static readonly string[] _rsa = { "root_rsa_2020", "nca_rsa_2022" };
    private static readonly string[] _gost = { "root_gost_2022", "nca_gost_2022" };
    private static readonly string[] _all = { "root_rsa_2020", "nca_rsa_2022", "root_gost_2022", "nca_gost_2022" };

    private static readonly Dictionary<string, X509Certificate2> _cache = new();
    private static readonly object _lock = new();

    private static IReadOnlyList<X509Certificate2> GetCached(string[] names)
    {
        lock (_lock)
        {
            var result = new List<X509Certificate2>(names.Length);
            foreach (var name in names)
            {
                if (!_cache.TryGetValue(name, out var cert))
                {
                    cert = LoadEmbedded(name);
                    _cache[name] = cert;
                }
                result.Add(cert);
            }
            return result;
        }
    }

    private static X509Certificate2 LoadEmbedded(string name)
    {
        var asm = typeof(EgovTrustRoots).Assembly;
        var resourceName = $"EgovHelper.Net.Resources.{name}.cer";
        using var stream = asm.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException(
                $"Embedded NUC RK root '{resourceName}' not found in {asm.GetName().Name}. " +
                "If you forked this package, ensure the .cer files in Resources/ are still " +
                "marked as <EmbeddedResource>.");
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return new X509Certificate2(ms.ToArray());
    }
}
