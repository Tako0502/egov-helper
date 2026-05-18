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
     *   "inline"   — caller passed documentBase64
     *   "legal:role/type/version/language" — fetched from LEGAL_DOC_BASE_URL with these params
     *   "embedded" — CMS was attached, doc was inside it
     *   "none"     — verified an attached CMS with no extra cross-check
     */
    @JsonProperty("documentSource") public String documentSource;
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
