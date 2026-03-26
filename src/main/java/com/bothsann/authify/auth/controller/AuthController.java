package com.bothsann.authify.auth.controller;

import com.bothsann.authify.auth.dto.*;
import com.bothsann.authify.auth.service.AuthService;
import com.bothsann.authify.common.response.ApiResponse;
import com.bothsann.authify.passwordreset.service.PasswordResetService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Exposes the public authentication endpoints under {@code /api/auth}.
 *
 * <p>All routes in this controller are explicitly permitted without authentication
 * in {@code SecurityConfig} ({@code POST /api/auth/**} and {@code GET /api/auth/**}
 * are {@code permitAll()}).
 *
 * <p>Every request body is annotated with {@code @Valid} so that Jakarta Bean Validation
 * runs before the method body executes. Validation failures are caught by
 * {@code GlobalExceptionHandler} and returned as a structured 400 error.
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final PasswordResetService passwordResetService;

    /**
     * Registers a new user account and returns a token pair.
     *
     * <p>Returns 201 Created (not 200 OK) because a new resource (the user account)
     * was created as a result of this request.
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<AuthResponseDto>> register(
            @Valid @RequestBody RegisterRequestDto request) {
        AuthResponseDto response = authService.register(request);
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(ApiResponse.of(201, response, "Registration successful"));
    }

    /**
     * Authenticates a user and returns a token pair.
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponseDto>> login(
            @Valid @RequestBody LoginRequestDto request) {
        AuthResponseDto response = authService.login(request);
        return ResponseEntity.ok(ApiResponse.success(response, "Login successful"));
    }

    /**
     * Validates a refresh token, rotates it, and returns a new token pair.
     *
     * <p>Token rotation means the old refresh token is invalidated after this call.
     * The client must use the new refresh token returned here for the next refresh.
     */
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponseDto>> refreshToken(
            @Valid @RequestBody RefreshTokenRequestDto request) {
        AuthResponseDto response = authService.refreshToken(request);
        return ResponseEntity.ok(ApiResponse.success(response, "Token refreshed successfully"));
    }

    /**
     * Revokes the user's refresh token, ending their session server-side.
     *
     * <p>The access token will expire naturally after 15 minutes. The client should
     * discard both tokens immediately upon receiving this response.
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @Valid @RequestBody RefreshTokenRequestDto request) {
        authService.logout(request);
        return ResponseEntity.ok(ApiResponse.success("Logged out successfully"));
    }

    /**
     * Initiates the password reset flow by sending a reset link to the user's email.
     *
     * <p>Always returns 200 OK regardless of whether the email exists in the database.
     * This prevents user enumeration — an attacker cannot determine which emails are
     * registered by probing this endpoint.
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<Void>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequestDto request) {
        passwordResetService.initiatePasswordReset(request);
        // Return the same message whether or not the email was found — no enumeration
        return ResponseEntity.ok(ApiResponse.success(
                "If that email is registered, a reset link has been sent."));
    }

    /**
     * Validates a password reset token and updates the user's password.
     *
     * <p>The token is single-use: it is marked {@code used = true} after a successful
     * reset. Any subsequent attempt with the same token returns 400.
     */
    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<Void>> resetPassword(
            @Valid @RequestBody PasswordResetRequestDto request) {
        passwordResetService.resetPassword(request);
        return ResponseEntity.ok(ApiResponse.success("Password updated successfully"));
    }
}
