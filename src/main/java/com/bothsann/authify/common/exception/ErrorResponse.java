package com.bothsann.authify.common.exception;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Standard error response body returned by {@link GlobalExceptionHandler} for every
 * non-2xx response.
 *
 * <p>All fields except {@code fieldErrors} are always populated. {@code fieldErrors}
 * is only present (non-null) when a {@code MethodArgumentNotValidException} is caught —
 * it maps each invalid field name to its constraint violation message.
 *
 * <p>Example (validation failure):
 * <pre>
 * {
 *   "status": 400,
 *   "error": "Bad Request",
 *   "message": "Validation failed",
 *   "timestamp": "2024-03-20T10:30:00",
 *   "path": "/api/auth/register",
 *   "fieldErrors": {
 *     "email": "must be a valid email address",
 *     "password": "must contain at least one uppercase letter"
 *   }
 * }
 * </pre>
 *
 * <p>Example (business logic error):
 * <pre>
 * {
 *   "status": 409,
 *   "error": "Conflict",
 *   "message": "Email already in use",
 *   "timestamp": "2024-03-20T10:30:00",
 *   "path": "/api/auth/register"
 * }
 * </pre>
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ErrorResponse {

    /** HTTP status code (e.g. 400, 401, 404, 409, 500). */
    private int status;

    /** Short human-readable reason phrase (e.g. "Bad Request", "Unauthorized"). */
    private String error;

    /** Application-level error message describing what went wrong. */
    private String message;

    /** Server time when the error occurred. */
    private LocalDateTime timestamp;

    /** The request URI that triggered this error (from {@code HttpServletRequest.getRequestURI()}). */
    private String path;

    /**
     * Per-field validation errors. Only populated for {@code MethodArgumentNotValidException}.
     * Key = field name, Value = constraint violation message.
     * Null for all other exception types.
     */
    private Map<String, String> fieldErrors;
}
