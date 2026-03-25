package com.bothsann.authify.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Request body for {@code POST /api/auth/login}.
 *
 * <p>The raw password here is passed into
 * {@code authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password))}.
 * {@code CustomAuthenticationProvider} loads the user and calls
 * {@code passwordEncoder.matches(raw, hashed)} to verify.
 */
@Data
public class LoginRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Must be a valid email address")
    private String email;

    @NotBlank(message = "Password is required")
    private String password;
}
