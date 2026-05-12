package kz.atasuai.egovsigner.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Mirror of `BackendCertInfo` in src/sign.ts. Hydrated to a JS `CertInfo` on the client. */
public final class CertInfoDto {
    @JsonProperty("bin") public String bin;
    @JsonProperty("iin") public String iin;
    @JsonProperty("commonName") public String commonName;
    @JsonProperty("surname") public String surname;
    @JsonProperty("givenName") public String givenName;
    @JsonProperty("organization") public String organization;
    @JsonProperty("email") public String email;
    /** "AUTH" | "SIGN" | "UNKNOWN" */
    @JsonProperty("keyUsage") public String keyUsage = "UNKNOWN";
    @JsonProperty("validFromIso") public String validFromIso;
    @JsonProperty("validToIso") public String validToIso;
    @JsonProperty("serialNumberHex") public String serialNumberHex;
    @JsonProperty("certificatePem") public String certificatePem;
}
