package com.bothsann.authify.auth.dto;

/**
 * Response body returned on successful register, login, and token refresh.
 *
 * <p>Contains both an access token and a refresh token:
 * <ul>
 *   <li>{@code accessToken} — short-lived JWT (15 minutes); sent in
 *       {@code Authorization: Bearer <token>} on every protected request</li>
 *   <li>{@code refreshToken} — long-lived opaque UUID string (7 days); stored by the
 *       client and sent to {@code POST /api/auth/refresh} when the access token expires</li>
 * </ul>
 *
 * <p>The client should store the refresh token securely (e.g., in an HttpOnly cookie
 * or secure storage) — never in localStorage where XSS can reach it.
 */
public record AuthResponse(

        /** Short-lived JWT for authenticating API requests. */
        String accessToken,

        /** Long-lived opaque token for obtaining new access tokens without re-login. */
        String refreshToken

) {}
