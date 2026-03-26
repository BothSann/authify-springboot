package com.bothsann.authify.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request body for {@code PUT /api/users/me}.
 *
 * <p>Only name fields are updatable through this endpoint. Email and password changes
 * would require separate flows (email verification, current-password confirmation)
 * that are out of scope for this version of Authify.
 */
public record UpdateProfileRequest(

        @NotBlank(message = "First name is required")
        @Size(min = 2, max = 50, message = "First name must be between 2 and 50 characters")
        String firstName,

        @NotBlank(message = "Last name is required")
        @Size(min = 2, max = 50, message = "Last name must be between 2 and 50 characters")
        String lastName

) {}
