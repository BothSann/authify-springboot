package com.bothsann.authify.auth.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Request body for both {@code POST /api/auth/refresh} and {@code POST /api/auth/logout}.
 *
 * <p>The refresh token is an opaque UUID string stored in the {@code refresh_tokens} table.
 * The client must include the exact string received during login or the last refresh call.
 */
public record RefreshTokenRequest(

        @NotBlank(message = "Refresh token is required")
        String refreshToken

) {}
