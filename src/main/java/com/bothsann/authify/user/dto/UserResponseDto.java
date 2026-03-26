package com.bothsann.authify.user.dto;

import com.bothsann.authify.user.entity.Role;
import com.bothsann.authify.user.entity.User;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Safe representation of a {@link User} for API responses.
 *
 * <p>This DTO deliberately omits the {@code password} field — passwords must NEVER
 * be returned in any response, even as a hashed value. Using a dedicated response DTO
 * (rather than the entity directly) makes this impossible to accidentally break.
 *
 * <p>Use the {@link #from(User)} factory method to convert an entity to this DTO.
 */
public record UserResponseDto(

        UUID id,
        String email,
        String firstName,
        String lastName,
        Role role,
        boolean enabled,
        LocalDateTime createdAt,
        LocalDateTime updatedAt

) {

    /**
     * Converts a {@link User} entity to a {@link UserResponseDto} DTO.
     *
     * <p>This static factory is the single place where the entity-to-DTO mapping is
     * defined. Callers (controllers and services) use this method rather than the
     * constructor directly, keeping the mapping logic centralized.
     *
     * @param user the entity to convert
     * @return a {@code UserResponseDto} with all fields populated (excluding {@code password})
     */
    public static UserResponseDto from(User user) {
        return new UserResponseDto(
                user.getId(),
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.getRole(),
                user.isEnabled(),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }
}
