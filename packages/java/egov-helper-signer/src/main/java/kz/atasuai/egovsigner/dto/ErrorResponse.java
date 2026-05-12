package kz.atasuai.egovsigner.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Single-field error response. The JS lib reads `error` and surfaces it via thrown Error. */
public final class ErrorResponse {
    @JsonProperty("error") public final String error;

    public ErrorResponse(String error) { this.error = error; }
}
