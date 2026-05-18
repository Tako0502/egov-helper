package kz.atasuai.egovsigner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.regex.Pattern;

/**
 * Fetches the canonical PDF of a legal document from the Atasuai legal-docs service so
 * `/cms/verify` can confirm "did this user sign THIS exact contract?" without trusting the
 * client to ship the doc bytes back.
 *
 * The URL is built from {@code LEGAL_DOC_BASE_URL} plus four query params:
 *   {@code ?role=<role>&type=<type>&version=<version>&language=<language>}
 *
 * Param values are URL-encoded, and each is also validated against a strict character
 * whitelist before encoding so a bad/malicious client can't inject path segments, additional
 * query params, or schemes.
 *
 * Configurable via env: {@code LEGAL_DOC_BASE_URL}, {@code LEGAL_DOC_TIMEOUT_MS}.
 */
public final class LegalDocFetcher {
    private static final Logger log = LoggerFactory.getLogger(LegalDocFetcher.class);

    /** Per-param whitelist. We're conservative: letters / digits / dash / underscore / dot. */
    private static final Pattern SAFE_PARAM = Pattern.compile("^[A-Za-z0-9._-]+$");

    /** Cap on the doc we'll fetch (8 MB) — guards against pathological responses. */
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

    /**
     * Build the URL, GET it, return the PDF bytes.
     * @throws IllegalArgumentException for caller-side errors (missing param, bad param chars,
     *                                  fetcher not configured)
     * @throws java.io.IOException      for network / upstream-status errors
     */
    public byte[] fetch(String role, String type, String version, String language)
            throws java.io.IOException, InterruptedException {
        if (!isConfigured()) {
            throw new IllegalArgumentException(
                "Legal-doc fetch is not configured on this server. " +
                "Either pass documentBase64 in the request, or set LEGAL_DOC_BASE_URL.");
        }
        requireSafe("role", role);
        requireSafe("type", type);
        requireSafe("version", version);
        requireSafe("language", language);

        // Build URL. Param order matches the integration spec (role, type, version, language).
        String url = baseUrl
            + "?role="     + URLEncoder.encode(role,     StandardCharsets.UTF_8)
            + "&type="     + URLEncoder.encode(type,     StandardCharsets.UTF_8)
            + "&version="  + URLEncoder.encode(version,  StandardCharsets.UTF_8)
            + "&language=" + URLEncoder.encode(language, StandardCharsets.UTF_8);

        log.debug("fetching legal doc: {}", url);

        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(timeout)
            .header("Accept", "application/pdf, application/octet-stream, */*")
            .GET()
            .build();

        HttpResponse<byte[]> resp = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new java.io.IOException(
                "Legal-doc endpoint returned HTTP " + resp.statusCode() + " for " + url);
        }
        byte[] body = resp.body();
        if (body == null || body.length == 0) {
            throw new java.io.IOException("Legal-doc endpoint returned an empty body for " + url);
        }
        if (body.length > MAX_DOC_BYTES) {
            throw new java.io.IOException(
                "Legal-doc response is " + body.length + " bytes, exceeds cap of " + MAX_DOC_BYTES);
        }
        return body;
    }

    private static void requireSafe(String name, String value) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("Missing legal-doc param: " + name);
        }
        if (!SAFE_PARAM.matcher(value).matches()) {
            throw new IllegalArgumentException(
                "Legal-doc param '" + name + "' contains disallowed characters " +
                "(allowed: letters, digits, '.', '-', '_')");
        }
    }
}
