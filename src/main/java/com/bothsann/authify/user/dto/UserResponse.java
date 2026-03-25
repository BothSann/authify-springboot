package com.bothsann.authify.user.dto;

import com.bothsann.authify.user.Role;
import com.bothsann.authify.user.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

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
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserResponse {

    private UUID id;
    private String email;
    private String firstName;
    private String lastName;
    private Role role;
    private boolean enabled;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    /**
     * Converts a {@link User} entity to a {@link UserResponse} DTO.
     *
     * <p>This static factory is the single place where the entity-to-DTO mapping is
     * defined. Callers (controllers and services) use this method rather than the
     * builder directly, keeping the mapping logic centralized.
     *
     * @param user the entity to convert
     * @return a {@code UserResponse} with all fields populated (excluding {@code password})
     */
    public static UserResponse from(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .role(user.getRole())
                .enabled(user.isEnabled())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .build();
    }
}
