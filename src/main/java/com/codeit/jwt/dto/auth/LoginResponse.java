package com.codeit.jwt.dto.auth;

import com.fasterxml.jackson.annotation.JsonProperty;

public record LoginResponse(

        @JsonProperty("access_token")
        String accessToken,

        @JsonProperty("refresh_token")
        String refreshToken,

        @JsonProperty("token_type")
        String tokenType,

        @JsonProperty("expires_in")
        Long expiresIn
) {

    public static LoginResponse of(String accessToken, String refreshToken, Long expiresIn) {
        return new LoginResponse(accessToken, refreshToken, "Bearer", expiresIn);
    }
}
