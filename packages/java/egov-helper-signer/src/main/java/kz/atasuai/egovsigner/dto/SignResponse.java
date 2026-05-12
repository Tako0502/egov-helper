package kz.atasuai.egovsigner.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Mirror of `BackendSignResponse` in src/sign.ts. */
public final class SignResponse {
    @JsonProperty("signatureBase64")
    public String signatureBase64;

    @JsonProperty("signedAtIso")
    public String signedAtIso;

    @JsonProperty("detached")
    public boolean detached;

    @JsonProperty("certInfo")
    public CertInfoDto certInfo;
}
