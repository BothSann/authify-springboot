package com.bothsann.authify.common.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Centralized exception handler for all exceptions thrown within the Spring MVC layer
 * (controllers and services they call).
 *
 * <h2>Important scope limitation</h2>
 *
 * <p>{@code @RestControllerAdvice} only intercepts exceptions that propagate out of
 * a controller method. Exceptions thrown in the <em>filter chain</em> (before the
 * {@code DispatcherServlet} is reached) are NOT handled here — those are handled by
 * the {@code AuthenticationEntryPoint} and {@code AccessDeniedHandler} configured in
 * {@code SecurityConfig}.
 *
 * <p>This means:
 * <ul>
 *   <li>A missing or invalid JWT → rejected at the filter level → 401 from
 *       {@code AuthenticationEntryPoint} (NOT this class)</li>
 *   <li>A bad email/password during login → thrown from {@code AuthServiceImpl} which
 *       calls {@code authenticationManager.authenticate()} → that call runs inside the
 *       controller's execution context → caught here as {@code BadCredentialsException}</li>
 * </ul>
 *
 * <h2>Response format</h2>
 *
 * <p>All handlers return an {@link ErrorResponse} object, which Jackson serializes to JSON.
 * The {@code path} field is populated from {@code HttpServletRequest.getRequestURI()}.
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    // ─── Validation (400) ────────────────────────────────────────────────────────

    /**
     * Handles Bean Validation failures from {@code @Valid} on request body parameters.
     *
     * <p>Collects ALL field-level violations into a {@code fieldErrors} map rather than
     * returning just the first failure — so clients can fix all validation problems in
     * one round trip.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse handleValidationException(
            MethodArgumentNotValidException ex, HttpServletRequest request) {

        // Collect every field error: { "email" → "must be a valid email", ... }
        Map<String, String> fieldErrors = new HashMap<>();
        for (FieldError fieldError : ex.getBindingResult().getFieldErrors()) {
            fieldErrors.put(fieldError.getField(), fieldError.getDefaultMessage());
        }

        return ErrorResponse.builder()
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Bad Request")
                .message("Validation failed")
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .fieldErrors(fieldErrors)
                .build();
    }

    /**
     * Handles attempts to register with an email that already exists in the database.
     */
    @ExceptionHandler(UserAlreadyExistsException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public ErrorResponse handleUserAlreadyExists(
            UserAlreadyExistsException ex, HttpServletRequest request) {
        return buildError(HttpStatus.CONFLICT, "Conflict", ex.getMessage(), request);
    }

    /**
     * Handles malformed, already-used, or unknown tokens (refresh or reset).
     */
    @ExceptionHandler(InvalidTokenException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse handleInvalidToken(
            InvalidTokenException ex, HttpServletRequest request) {
        return buildError(HttpStatus.BAD_REQUEST, "Bad Request", ex.getMessage(), request);
    }

    // ─── Authentication / Authorization (401 / 403) ──────────────────────────────

    /**
     * Handles expired tokens (refresh tokens and password reset tokens).
     */
    @ExceptionHandler(TokenExpiredException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ErrorResponse handleTokenExpired(
            TokenExpiredException ex, HttpServletRequest request) {
        return buildError(HttpStatus.UNAUTHORIZED, "Unauthorized", ex.getMessage(), request);
    }

    /**
     * Handles explicit auth failures raised in the service layer.
     */
    @ExceptionHandler(UnauthorizedException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ErrorResponse handleUnauthorized(
            UnauthorizedException ex, HttpServletRequest request) {
        return buildError(HttpStatus.UNAUTHORIZED, "Unauthorized", ex.getMessage(), request);
    }

    /**
     * Handles bad credentials on login.
     *
     * <p>{@code BadCredentialsException} is thrown by {@code CustomAuthenticationProvider}
     * when the password doesn't match. Because the call to
     * {@code authenticationManager.authenticate()} originates inside a controller method
     * (via {@code AuthServiceImpl}), it propagates through the MVC layer and is caught here
     * — unlike filter-level auth failures which bypass this handler entirely.
     */
    @ExceptionHandler(BadCredentialsException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ErrorResponse handleBadCredentials(
            BadCredentialsException ex, HttpServletRequest request) {
        // Return a generic message — don't leak whether email or password was wrong
        return buildError(HttpStatus.UNAUTHORIZED, "Unauthorized",
                "Invalid email or password", request);
    }

    /**
     * Handles method-level access denial (e.g., {@code @PreAuthorize} failures for
     * authenticated users who lack the required role).
     *
     * <p>Note: route-level denials (from {@code SecurityFilterChain} authorization rules)
     * are handled by {@code AccessDeniedHandler} in {@code SecurityConfig} and do NOT
     * reach this handler.
     */
    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ErrorResponse handleAccessDenied(
            AccessDeniedException ex, HttpServletRequest request) {
        return buildError(HttpStatus.FORBIDDEN, "Forbidden", "Insufficient permissions", request);
    }

    // ─── Not Found (404) ─────────────────────────────────────────────────────────

    /**
     * Handles lookups that find no matching entity in the database.
     */
    @ExceptionHandler(ResourceNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ErrorResponse handleResourceNotFound(
            ResourceNotFoundException ex, HttpServletRequest request) {
        return buildError(HttpStatus.NOT_FOUND, "Not Found", ex.getMessage(), request);
    }

    // ─── Catch-all (500) ─────────────────────────────────────────────────────────

    /**
     * Catch-all for any unexpected exception not matched by the handlers above.
     *
     * <p>Logs the full stack trace (important for debugging) but returns a generic
     * message to the client — never expose internal details in a 500 response.
     */
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ErrorResponse handleGenericException(Exception ex, HttpServletRequest request) {
        log.error("Unhandled exception at {}: {}", request.getRequestURI(), ex.getMessage(), ex);
        return buildError(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error",
                "An unexpected error occurred", request);
    }

    // ─── Private helper ──────────────────────────────────────────────────────────

    private ErrorResponse buildError(
            HttpStatus status, String error, String message, HttpServletRequest request) {
        return ErrorResponse.builder()
                .status(status.value())
                .error(error)
                .message(message)
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();
    }
}
