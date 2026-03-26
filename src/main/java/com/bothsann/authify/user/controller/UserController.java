package com.bothsann.authify.user.controller;

import com.bothsann.authify.common.response.ApiResponse;
import com.bothsann.authify.user.dto.UpdateProfileRequestDto;
import com.bothsann.authify.user.dto.UserResponseDto;
import com.bothsann.authify.user.entity.User;
import com.bothsann.authify.user.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

/**
 * Exposes authenticated user profile endpoints under {@code /api/users}.
 *
 * <p>All endpoints here require an authenticated user (any role). The JWT filter
 * must have validated the Bearer token and populated {@code SecurityContextHolder}
 * before these methods are reached.
 *
 * <h2>How {@code @AuthenticationPrincipal} works here</h2>
 *
 * <p>In {@code JwtAuthFilter}, the {@code UsernamePasswordAuthenticationToken} is
 * constructed with the {@code UserDetails} object (which is the full {@link User}
 * entity, since {@code User implements UserDetails}) as the principal:
 * <pre>
 *   new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities())
 * </pre>
 *
 * <p>{@code @AuthenticationPrincipal} extracts that principal from the
 * {@code SecurityContext}. Declaring the parameter as {@code User} works because
 * the stored principal IS a {@code User} instance.
 *
 * <p>Note: the {@code User} entity retrieved this way was loaded in {@code JwtAuthFilter}
 * during the current request. It is a detached entity (outside any transaction at the
 * controller boundary), but all non-lazy fields (like {@code email}, {@code role}) are
 * fully populated and safe to read.
 */
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;

    /**
     * Returns the currently authenticated user's profile.
     *
     * <p>We pass the email to the service rather than the whole entity to keep the
     * service layer decoupled from the security context — the service just needs an
     * identifier to load the freshest data from the database.
     */
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserResponseDto>> getCurrentUser(
            @AuthenticationPrincipal User currentUser) {
        UserResponseDto response = userService.getCurrentUser(currentUser.getEmail());
        return ResponseEntity.ok(ApiResponse.success(response, "User profile retrieved"));
    }

    /**
     * Updates the currently authenticated user's first and last name.
     */
    @PutMapping("/me")
    public ResponseEntity<ApiResponse<UserResponseDto>> updateCurrentUser(
            @AuthenticationPrincipal User currentUser,
            @Valid @RequestBody UpdateProfileRequestDto request) {
        UserResponseDto response = userService.updateCurrentUser(currentUser.getEmail(), request);
        return ResponseEntity.ok(ApiResponse.success(response, "Profile updated successfully"));
    }
}
