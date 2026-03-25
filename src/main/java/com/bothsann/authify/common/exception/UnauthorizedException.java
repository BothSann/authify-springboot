package com.bothsann.authify.common.exception;

/**
 * Thrown for explicit authentication failures that originate in the service layer
 * (as opposed to Spring Security's filter-level rejections, which are handled by
 * {@code AuthenticationEntryPoint} in {@code SecurityConfig}).
 *
 * <p>Maps to HTTP 401 Unauthorized in {@link GlobalExceptionHandler}.
 *
 * <p>Note: most 401 responses in this API come from either Spring Security's
 * {@code AuthenticationEntryPoint} (for missing/invalid JWT at the filter level)
 * or {@code BadCredentialsException} (from {@code CustomAuthenticationProvider} on
 * bad login). This exception is reserved for business-logic-level auth failures
 * not covered by those two paths.
 */
public class UnauthorizedException extends RuntimeException {

    public UnauthorizedException(String message) {
        super(message);
    }
}
