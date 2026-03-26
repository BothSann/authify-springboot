package com.bothsann.authify.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Request body for {@code POST /api/auth/register}.
 *
 * <p>All fields are validated with Jakarta Bean Validation. Violations are caught by
 * {@code GlobalExceptionHandler} and returned as a 400 response with per-field error messages.
 */
public record RegisterRequestDto(

        @NotBlank(message = "Email is required")
        @Email(message = "Must be a valid email address")
        String email,

        /**
         * Raw (unhashed) password. Must be 8–64 characters and contain:
         * <ul>
         *   <li>At least one uppercase letter (A–Z)</li>
         *   <li>At least one digit (0–9)</li>
         *   <li>At least one special character from {@code @#$%^&+=}</li>
         * </ul>
         * The password is BCrypt-hashed in {@code AuthServiceImpl} before it is ever persisted.
         */
        @NotBlank(message = "Password is required")
        @Size(min = 8, max = 64, message = "Password must be between 8 and 64 characters")
        @Pattern(
                regexp = "^(?=.*[A-Z])(?=.*[0-9])(?=.*[@#$%^&+=]).*$",
                message = "Password must contain at least one uppercase letter, number, and special character"
        )
        String password,

        @NotBlank(message = "First name is required")
        @Size(min = 2, max = 50, message = "First name must be between 2 and 50 characters")
        String firstName,

        @NotBlank(message = "Last name is required")
        @Size(min = 2, max = 50, message = "Last name must be between 2 and 50 characters")
        String lastName

) {}
