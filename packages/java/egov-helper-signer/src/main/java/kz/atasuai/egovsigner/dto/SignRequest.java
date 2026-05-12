package kz.atasuai.egovsigner.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Wire request shape that the JS lib's `transport: 'backend'` sends.
 * Match `BackendSignRequest` in src/sign.ts exactly.
 *
 * `password` is sensitive — never log this object's `toString()`, never persist.
 */
public final class SignRequest {
    @JsonProperty("p12Base64")
    public String p12Base64;

    @JsonProperty("password")
    public String password;

    @JsonProperty("documentBase64")
    public String documentBase64;

    @JsonProperty("detached")
    public boolean detached = true;

    /** "auto" | "SHA-256" | "SHA-384" | "SHA-512". For GOST keys the backend picks Stribog regardless. */
    @JsonProperty("hashAlgorithm")
    public String hashAlgorithm = "auto";

    @Override
    public String toString() {
        // Deliberately omits p12Base64 and password.
        return "SignRequest{detached=" + detached +
            ", hashAlgorithm=" + hashAlgorithm +
            ", docBytes=" + (documentBase64 == null ? 0 : documentBase64.length()) + " (base64)}";
    }
}
