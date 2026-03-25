package com.bothsann.authify.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Request body for {@code POST /api/auth/reset-password}.
 *
 * <p>The {@code token} is the opaque UUID value embedded in the reset link sent by email:
 * {@code <frontend-url>/reset-password?token=<token>}
 *
 * <p>The {@code newPassword} must meet the same strength requirements as during
 * registration. It is BCrypt-hashed in {@code PasswordResetService} before being saved.
 */
@Data
public class PasswordResetRequest {

    @NotBlank(message = "Reset token is required")
    private String token;

    @NotBlank(message = "New password is required")
    @Size(min = 8, max = 64, message = "Password must be between 8 and 64 characters")
    @Pattern(
            regexp = "^(?=.*[A-Z])(?=.*[0-9])(?=.*[@#$%^&+=]).*$",
            message = "Password must contain at least one uppercase letter, number, and special character"
    )
    private String newPassword;
}
