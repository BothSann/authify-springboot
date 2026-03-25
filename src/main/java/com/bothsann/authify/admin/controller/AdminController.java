package com.bothsann.authify.admin.controller;

import com.bothsann.authify.common.response.ApiResponse;
import com.bothsann.authify.user.dto.UserResponse;
import com.bothsann.authify.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Admin-only endpoints for user management under {@code /api/admin}.
 *
 * <h2>Two layers of authorization</h2>
 *
 * <p>These routes are protected at two levels:
 * <ol>
 *   <li><strong>Route-level</strong> — {@code SecurityConfig} declares
 *       {@code .requestMatchers("/api/admin/**").hasRole("ADMIN")}, so any request
 *       reaching this controller has already been verified to carry an ADMIN role JWT.</li>
 *   <li><strong>Method-level</strong> — {@code @PreAuthorize("hasRole('ADMIN')")} on
 *       the class (enabled by {@code @EnableMethodSecurity} in {@code SecurityConfig})
 *       provides a second check. This is "defense in depth" — if the route-level rule
 *       is ever accidentally removed, the method-level check still protects the endpoint.</li>
 * </ol>
 *
 * <p>Note: {@code SecurityConfig} uses {@code hasRole("ADMIN")} which checks for the
 * authority {@code "ROLE_ADMIN"} (Spring adds the prefix automatically). {@code @PreAuthorize}
 * with {@code hasRole('ADMIN')} does the same.
 */
@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@Slf4j
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final UserService userService;

    /**
     * Returns a list of all registered users.
     *
     * <p>Passwords are never included — the response uses {@link UserResponse} which
     * is a safe DTO that omits the password field.
     */
    @GetMapping("/users")
    public ResponseEntity<ApiResponse<List<UserResponse>>> getAllUsers() {
        List<UserResponse> users = userService.getAllUsers();
        return ResponseEntity.ok(ApiResponse.success(users,
                "Retrieved " + users.size() + " user(s)"));
    }

    /**
     * Permanently deletes a user by their UUID.
     *
     * <p>This is a hard delete — the user record and all associated tokens are removed
     * from the database. The {@code ON DELETE CASCADE} constraints on {@code refresh_tokens}
     * and {@code password_reset_tokens} handle the cascade automatically at the DB level.
     */
    @DeleteMapping("/users/{id}")
    public ResponseEntity<ApiResponse<Void>> deleteUser(@PathVariable UUID id) {
        userService.deleteUser(id);
        return ResponseEntity.ok(ApiResponse.success("User deleted successfully"));
    }
}
