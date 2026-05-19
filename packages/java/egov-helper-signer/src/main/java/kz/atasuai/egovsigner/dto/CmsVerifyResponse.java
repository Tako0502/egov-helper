package kz.atasuai.egovsigner.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response shape for `POST /cms/verify` — answers "did THIS user sign THIS document?"
 *
 * `valid` is the bottom line: true iff every per-signer check passed. Individual booleans
 * are exposed so the client can tell *why* a verification failed (sig forged vs. document
 * tampered vs. cert expired).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class CmsVerifyResponse {
    /** Overall verdict: true iff every signer's signature verifies AND the document digest matches. */
    @JsonProperty("valid") public boolean valid;
    /** Was the CMS detached? (true when the caller supplied documentBase64 — false if the doc is embedded.) */
    @JsonProperty("detached") public boolean detached;
    /**
     * Where the bytes we hashed came from:
     *   "inline"               — caller passed documentBase64
     *   "legal:role/type"      — fetched from LEGAL_DOC_BASE_URL; matchedLanguage tells you which variant matched
     *   "embedded"             — CMS was attached, doc was inside it
     *   "none"                 — verified an attached CMS with no extra cross-check
     */
    @JsonProperty("documentSource") public String documentSource;
    /**
     * For the legal-doc fetch path: the language whose bytes hash-matched the CMS's
     * messageDigest (e.g. "ru" when the user signed the Russian version even though the
     * verifier asked for the Kazakh version). Null when verification used an inline doc
     * or no language matched.
     */
    @JsonProperty("matchedLanguage") public String matchedLanguage;
    /**
     * For the legal-doc fetch path: the language codes we hashed against the CMS while
     * looking for a match, in the order tried. Useful for "I asked for kz but ru matched —
     * that's expected if the user signed the Russian variant." Null when not applicable.
     */
    @JsonProperty("languagesTried") public java.util.List<String> languagesTried;
    /**
     * Set when verification could not complete because of an upstream/internal failure
     * (e.g. legal-doc fetch returned 404, network timeout, malformed CMS bytes). The
     * response status code is intentionally 200 — Cloudflare and other edge proxies
     * tend to replace 5xx bodies with their own error pages, hiding this message from
     * callers. When `error` is present, `valid` is always false and the rest of the
     * fields may be empty.
     */
    @JsonProperty("error") public String error;
    /** Per-signer detail. eGov Mobile produces exactly one; corporate flows may have more. */
    @JsonProperty("signers") public java.util.List<SignerVerifyResult> signers = new java.util.ArrayList<>();

    public static final class SignerVerifyResult {
        /** Signer's cert subject — BIN/IIN/CN/etc. */
        @JsonProperty("certInfo") public CertInfoDto certInfo;
        /** Signature over signedAttrs verifies against the cert's public key. */
        @JsonProperty("signatureValid") public boolean signatureValid;
        /** SHA/Stribog hash of the document matches the messageDigest attribute in the CMS. */
        @JsonProperty("documentDigestMatches") public Boolean documentDigestMatches;
        /** Was the cert still within its validity window at the claimed signing time? */
        @JsonProperty("certValidAtSigningTime") public Boolean certValidAtSigningTime;
        /** Digest algorithm OID (e.g. 2.16.840.1.101.3.4.2.1 for SHA-256, 1.2.643.7.1.1.2.3 for Stribog-512). */
        @JsonProperty("digestAlgorithmOid") public String digestAlgorithmOid;
        /** ISO-8601 signing time pulled from the signedAttrs (if present). */
        @JsonProperty("signedAtIso") public String signedAtIso;
    }
}
