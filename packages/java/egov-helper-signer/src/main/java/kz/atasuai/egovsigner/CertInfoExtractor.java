package kz.atasuai.egovsigner;

import kz.atasuai.egovsigner.dto.CertInfoDto;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extract BIN / IIN / CN / org / validity etc. from a NUC RK X.509 certificate.
 * Mirror of the JS `extractCertInfo()` in src/parse.ts so the wire shape is consistent.
 */
public final class CertInfoExtractor {

    private static final Pattern BIN_RE = Pattern.compile("BIN[\\s:=]*?(\\d{12})", Pattern.CASE_INSENSITIVE);
    private static final Pattern IIN_RE = Pattern.compile("IIN[\\s:=]*?(\\d{12})", Pattern.CASE_INSENSITIVE);

    public static CertInfoDto extract(X509Certificate cert) {
        Map<String, String> attrs = parseDn(cert.getSubjectX500Principal());

        String serialAttr = firstNonEmpty(attrs.get("SERIALNUMBER"), attrs.get("2.5.4.5"), "");
        String ou = firstNonEmpty(attrs.get("OU"), attrs.get("2.5.4.11"), "");

        String iin = matchKzId(serialAttr, IIN_RE);
        if (iin == null) iin = matchKzId(ou, IIN_RE);

        String bin = matchKzId(serialAttr, BIN_RE);
        if (bin == null) bin = matchKzId(ou, BIN_RE);

        CertInfoDto dto = new CertInfoDto();
        dto.bin = bin;
        dto.iin = iin;
        dto.commonName = nullIfBlank(firstNonEmpty(attrs.get("CN"), attrs.get("2.5.4.3")));
        dto.surname = nullIfBlank(firstNonEmpty(attrs.get("SN"), attrs.get("SURNAME"), attrs.get("2.5.4.4")));
        dto.givenName = nullIfBlank(firstNonEmpty(attrs.get("G"), attrs.get("GIVENNAME"), attrs.get("2.5.4.42")));
        dto.organization = nullIfBlank(firstNonEmpty(attrs.get("O"), attrs.get("2.5.4.10")));
        dto.email = nullIfBlank(firstNonEmpty(attrs.get("E"), attrs.get("EMAILADDRESS"), attrs.get("1.2.840.113549.1.9.1")));
        dto.keyUsage = detectKeyUsage(cert);
        dto.validFromIso = DateTimeFormatter.ISO_INSTANT.format(cert.getNotBefore().toInstant());
        dto.validToIso = DateTimeFormatter.ISO_INSTANT.format(cert.getNotAfter().toInstant());
        dto.serialNumberHex = cert.getSerialNumber().toString(16);
        dto.certificatePem = toPem(cert);
        return dto;
    }

    private static Map<String, String> parseDn(X500Principal subject) {
        Map<String, String> result = new HashMap<>();
        // Use OID format so we get the raw OIDs for the unusual KZ attributes.
        // RFC2253 format keeps OIDs like "2.5.4.5" instead of converting to "SERIALNUMBER".
        String rfc2253 = subject.getName(X500Principal.RFC2253);
        // Lazy parser — KZ NUC certs don't use escaped commas inside values.
        for (String part : rfc2253.split(",")) {
            int eq = part.indexOf('=');
            if (eq <= 0) continue;
            String key = part.substring(0, eq).trim().toUpperCase();
            String value = part.substring(eq + 1).trim();
            if (value.startsWith("\"") && value.endsWith("\"") && value.length() >= 2) {
                value = value.substring(1, value.length() - 1);
            }
            // RFC2253 hex-encodes some values as #XX. Decode if present.
            if (value.startsWith("#")) {
                value = decodeHexValue(value.substring(1));
            }
            result.putIfAbsent(key, value);
        }
        // Also try RFC1779 to pick up friendly names (CN, OU) the OID form missed.
        String rfc1779 = subject.getName(X500Principal.RFC1779);
        for (String part : rfc1779.split(",")) {
            int eq = part.indexOf('=');
            if (eq <= 0) continue;
            String key = part.substring(0, eq).trim().toUpperCase();
            String value = part.substring(eq + 1).trim();
            if (value.startsWith("\"") && value.endsWith("\"") && value.length() >= 2) {
                value = value.substring(1, value.length() - 1);
            }
            result.putIfAbsent(key, value);
        }
        return result;
    }

    private static String decodeHexValue(String hex) {
        // X.500 RFC 2253 hex-encoded values are DER bytes of the ASN.1 value (e.g. PrintableString,
        // UTF8String). For our purposes (BIN/IIN matching) we just want the visible string content,
        // and DER-encoded UTF8String values have the form: 0C LL <utf8 bytes>. Skip the 2-byte header.
        if (hex.length() < 4) return hex;
        try {
            byte[] der = hexToBytes(hex);
            if (der.length >= 2 && (der[0] & 0xff) == 0x0C) {
                int len = der[1] & 0xff;
                return new String(der, 2, Math.min(len, der.length - 2), java.nio.charset.StandardCharsets.UTF_8);
            }
            // PrintableString tag 0x13 — same layout.
            if (der.length >= 2 && (der[0] & 0xff) == 0x13) {
                int len = der[1] & 0xff;
                return new String(der, 2, Math.min(len, der.length - 2), java.nio.charset.StandardCharsets.US_ASCII);
            }
        } catch (Exception ignored) { /* fall through */ }
        return hex; // best-effort fallback
    }

    private static byte[] hexToBytes(String hex) {
        int n = hex.length();
        byte[] out = new byte[n / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String detectKeyUsage(X509Certificate cert) {
        try {
            List<String> ekuOids = cert.getExtendedKeyUsage();
            if (ekuOids == null) return "UNKNOWN";
            if (ekuOids.contains("1.3.6.1.5.5.7.3.2")) return "AUTH"; // clientAuth
            if (ekuOids.contains("1.3.6.1.5.5.7.3.4")) return "SIGN"; // emailProtection (NUC RK signing certs)
            return "UNKNOWN";
        } catch (Exception e) {
            return "UNKNOWN";
        }
    }

    private static String toPem(X509Certificate cert) {
        try {
            String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded());
            return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
        } catch (Exception e) {
            return "";
        }
    }

    private static String matchKzId(String value, Pattern p) {
        if (value == null || value.isEmpty()) return null;
        Matcher m = p.matcher(value);
        return m.find() ? m.group(1) : null;
    }

    private static String firstNonEmpty(String... candidates) {
        for (String s : candidates) {
            if (s != null && !s.isEmpty()) return s;
        }
        return "";
    }

    private static String nullIfBlank(String s) {
        return s == null || s.isBlank() ? null : s;
    }

    private CertInfoExtractor() {}
}
