package com.bothsann.authify.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Request body for both {@code POST /api/auth/refresh} and {@code POST /api/auth/logout}.
 *
 * <p>The refresh token is an opaque UUID string stored in the {@code refresh_tokens} table.
 * The client must include the exact string received during login or the last refresh call.
 */
@Data
public class RefreshTokenRequest {

    @NotBlank(message = "Refresh token is required")
    private String refreshToken;
}
