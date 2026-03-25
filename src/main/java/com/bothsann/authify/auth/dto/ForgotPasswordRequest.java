package com.bothsann.authify.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Request body for {@code POST /api/auth/forgot-password}.
 *
 * <p>Contains only the user's email address. If the email is not found in the database,
 * the endpoint still returns 200 OK — this prevents user enumeration attacks where an
 * attacker could probe which emails are registered by observing the response status.
 */
@Data
public class ForgotPasswordRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Must be a valid email address")
    private String email;
}
