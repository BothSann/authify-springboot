package com.bothsann.authify.exception;

/**
 * Thrown when a token is structurally invalid, not found in the database,
 * or has already been consumed (used).
 *
 * <p>Maps to HTTP 400 Bad Request in {@link GlobalExceptionHandler}.
 *
 * <p>Distinct from {@link TokenExpiredException}: this exception means the token
 * is fundamentally unusable (wrong, unknown, or spent), whereas
 * {@code TokenExpiredException} means the token was valid but its time window passed.
 *
 * <p>Examples:
 * <ul>
 *   <li>Refresh token string not found in the database</li>
 *   <li>Password reset token that has already been marked {@code used = true}</li>
 *   <li>Malformed token string that cannot be parsed</li>
 * </ul>
 */
public class InvalidTokenException extends RuntimeException {

    public InvalidTokenException(String message) {
        super(message);
    }
}
