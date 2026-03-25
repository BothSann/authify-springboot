package com.bothsann.authify.common.exception;

/**
 * Thrown during registration when the provided email address is already associated
 * with an existing account.
 *
 * <p>Maps to HTTP 409 Conflict in {@link GlobalExceptionHandler}.
 *
 * <p>Note: we intentionally use 409 (Conflict) rather than 400 (Bad Request) because
 * the request itself is well-formed — the conflict is at the data layer (duplicate key),
 * not at the input validation layer.
 */
public class UserAlreadyExistsException extends RuntimeException {

    public UserAlreadyExistsException(String message) {
        super(message);
    }
}
