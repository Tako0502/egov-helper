package kz.atasuai.egovsigner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Fetches the canonical contract from the Atasuai legal-docs service so `/cms/verify`
 * can confirm "did this user sign THIS exact contract?" without trusting the client to
 * ship the doc bytes.
 *
 * Wire shape (post-2026-05-19 legal-docs schema):
 *   {@code GET {baseUrl}?role=<role>&type=<type>}
 *   → response 200 with JSON:
 *   {@code {
 *     "role": "seller",
 *     "contractType": "public-offer",
 *     "version": 1,
 *     "languages": [
 *       { "language": "kz", "fileSha256": "...", "fileSizeBytes": 12345, "base64": "..." },
 *       { "language": "ru", "fileSha256": "...", "fileSizeBytes": 12380, "base64": "..." }
 *     ]
 *   }}
 *
 * The handler then hashes each language's bytes with the signer's digest algorithm and
 * keeps the one whose hash matches the CMS messageDigest. {@code role}, {@code type} are
 * required; {@code language} and {@code version} are kept on the API for future use but
 * are not sent unless the caller passes them — the legal API gracefully ignores extras.
 *
 * Param values are URL-encoded and also validated against a strict character whitelist
 * before encoding so a bad/malicious client can't inject path segments, additional
 * query params, or schemes.
 *
 * Configurable via env: {@code LEGAL_DOC_BASE_URL}, {@code LEGAL_DOC_TIMEOUT_MS}.
 */
public final class LegalDocFetcher {
    private static final Logger log = LoggerFactory.getLogger(LegalDocFetcher.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    /** Per-param whitelist. We're conservative: letters / digits / dash / underscore / dot. */
    private static final Pattern SAFE_PARAM = Pattern.compile("^[A-Za-z0-9._-]+$");

    /** Cap on the doc we'll fetch (8 MB) per language — guards against pathological responses. */
    private static final long MAX_DOC_BYTES = 8L * 1024 * 1024;

    private final String baseUrl;
    private final HttpClient http;
    private final Duration timeout;

    public LegalDocFetcher(String baseUrl, int timeoutMs) {
        this.baseUrl = baseUrl == null ? "" : baseUrl.trim();
        this.timeout = Duration.ofMillis(timeoutMs);
        this.http = HttpClient.newBuilder()
            .connectTimeout(this.timeout)
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
    }

    public boolean isConfigured() {
        return !baseUrl.isEmpty();
    }

    /** One language variant of a fetched legal doc. */
    public static final class LangVariant {
        public final String language;     // "kz" / "ru" / "en"
        public final byte[] bytes;
        public final String declaredSha256;

        public LangVariant(String language, byte[] bytes, String declaredSha256) {
            this.language = language;
            this.bytes = bytes;
            this.declaredSha256 = declaredSha256;
        }
    }

    /**
     * GETs the legal-doc endpoint and returns every language variant the active version
     * publishes. The caller (CmsVerifyHandler) hashes each variant against the CMS's
     * messageDigest to find the match.
     *
     * @throws IllegalArgumentException for caller-side errors (missing/bad param, fetcher not configured)
     * @throws java.io.IOException      for network / upstream-status / parse errors
     */
    public List<LangVariant> fetchAllLanguages(String role, String type)
            throws java.io.IOException, InterruptedException {
        if (!isConfigured()) {
            throw new IllegalArgumentException(
                "Legal-doc fetch is not configured on this server. " +
                "Either pass documentBase64 in the request, or set LEGAL_DOC_BASE_URL.");
        }
        requireSafe("role", role);
        requireSafe("type", type);

        String finalUrl = baseUrl
            + "?role=" + URLEncoder.encode(role, StandardCharsets.UTF_8)
            + "&type=" + URLEncoder.encode(type, StandardCharsets.UTF_8);

        log.debug("fetching legal doc: {}", finalUrl);

        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(finalUrl))
            .timeout(timeout)
            .header("Accept", "application/json")
            .GET()
            .build();

        HttpResponse<byte[]> resp = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new java.io.IOException(
                "Legal-doc endpoint returned HTTP " + resp.statusCode() + " for " + finalUrl);
        }
        byte[] body = resp.body();
        if (body == null || body.length == 0) {
            throw new java.io.IOException("Legal-doc endpoint returned an empty body for " + finalUrl);
        }

        JsonNode root;
        try {
            root = JSON.readTree(body);
        } catch (Exception e) {
            throw new java.io.IOException("Legal-doc response was not valid JSON: " + e.getMessage());
        }

        // The all-languages response carries a `languages: [...]` array. If we got the
        // legacy single-language shape (caller set the URL to a path that requires
        // ?language=), surface a clear error rather than silently misbehaving.
        JsonNode langsNode = root.get("languages");
        if (langsNode == null || !langsNode.isArray() || langsNode.size() == 0) {
            // Be forgiving for the single-language shape: treat it as one variant.
            JsonNode base64Node = root.get("base64");
            JsonNode langNode = root.get("language");
            if (base64Node != null && base64Node.isTextual() && langNode != null && langNode.isTextual()) {
                byte[] one = decodeAndCheck(base64Node.asText(), langNode.asText());
                JsonNode shaNode = root.get("fileSha256");
                return Collections.singletonList(new LangVariant(
                    langNode.asText().toLowerCase(),
                    one,
                    shaNode != null ? shaNode.asText() : null
                ));
            }
            throw new java.io.IOException(
                "Legal-doc response has no `languages` array (got " + truncate(new String(body, StandardCharsets.UTF_8), 200) + ")");
        }

        List<LangVariant> out = new ArrayList<>(langsNode.size());
        for (JsonNode lang : langsNode) {
            JsonNode codeNode = lang.get("language");
            JsonNode b64Node = lang.get("base64");
            if (codeNode == null || !codeNode.isTextual()
                || b64Node == null || !b64Node.isTextual()) {
                continue;
            }
            String code = codeNode.asText().toLowerCase();
            byte[] decoded = decodeAndCheck(b64Node.asText(), code);
            JsonNode shaNode = lang.get("fileSha256");
            out.add(new LangVariant(code, decoded, shaNode != null ? shaNode.asText() : null));
        }
        if (out.isEmpty()) {
            throw new java.io.IOException("Legal-doc response `languages` array contained no valid entries");
        }
        return out;
    }

    private static byte[] decodeAndCheck(String base64, String tag) throws java.io.IOException {
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new java.io.IOException("Legal-doc `" + tag + "` base64 was invalid");
        }
        if (decoded.length == 0) {
            throw new java.io.IOException("Legal-doc `" + tag + "` decoded to zero bytes");
        }
        if (decoded.length > MAX_DOC_BYTES) {
            throw new java.io.IOException(
                "Legal-doc `" + tag + "` is " + decoded.length + " bytes, exceeds cap of " + MAX_DOC_BYTES);
        }
        return decoded;
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    private static void requireSafe(String name, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing legal-doc param: " + name);
        }
        if (!SAFE_PARAM.matcher(value).matches()) {
            throw new IllegalArgumentException(
                "Legal-doc param '" + name + "' contains disallowed characters " +
                "(allowed: letters, digits, '.', '-', '_')");
        }
    }
}
