package com.bothsann.authify.common.exception;

/**
 * Thrown when a requested resource (user, token, entity) cannot be found.
 *
 * <p>Maps to HTTP 404 Not Found in {@link GlobalExceptionHandler}.
 *
 * <p>Examples:
 * <ul>
 *   <li>Looking up a user by ID that doesn't exist</li>
 *   <li>Looking up a user by email that doesn't exist (non-enumeration contexts)</li>
 * </ul>
 */
public class ResourceNotFoundException extends RuntimeException {

    public ResourceNotFoundException(String message) {
        super(message);
    }
}
