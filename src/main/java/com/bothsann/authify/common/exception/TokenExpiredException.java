package com.bothsann.authify.common.exception;

/**
 * Thrown when a token was valid and recognized but its expiry timestamp has passed.
 *
 * <p>Maps to HTTP 401 Unauthorized in {@link GlobalExceptionHandler}.
 *
 * <p>Distinct from {@link InvalidTokenException}: expiry is a time-based condition on
 * an otherwise legitimate token, whereas {@code InvalidTokenException} covers structural
 * or data-integrity problems.
 *
 * <p>Examples:
 * <ul>
 *   <li>Refresh token whose {@code expiresAt} is in the past</li>
 *   <li>Password reset token whose 15-minute window has elapsed</li>
 * </ul>
 *
 * <p>When a refresh token is found to be expired, it is deleted from the database
 * before this exception is thrown, forcing the user to log in again.
 */
public class TokenExpiredException extends RuntimeException {

    public TokenExpiredException(String message) {
        super(message);
    }
}
