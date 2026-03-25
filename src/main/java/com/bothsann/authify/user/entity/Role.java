package com.bothsann.authify.user.entity;

/**
 * Represents the access role assigned to a user account.
 *
 * <p>Spring Security requires role names to be prefixed with {@code "ROLE_"} when
 * used with {@code hasRole()} checks. We store the raw name here ({@code USER},
 * {@code ADMIN}) and apply the prefix in {@link User#getAuthorities()}, so this enum
 * stays clean and the prefix logic lives in one place.
 */
public enum Role {
    USER,
    ADMIN
}
