package com.bothsann.authify.user.service;

import com.bothsann.authify.user.dto.UpdateProfileRequest;
import com.bothsann.authify.user.dto.UserResponse;

import java.util.List;
import java.util.UUID;

/**
 * User profile and account management operations.
 *
 * <p>Provides methods for both user-facing endpoints (get/update own profile) and
 * admin-facing endpoints (list all users, delete a user). Both {@link com.bothsann.authify.user.controller.UserController}
 * and {@link com.bothsann.authify.admin.controller.AdminController} depend on this interface.
 */
public interface UserService {

    /**
     * Returns the profile of the currently authenticated user.
     *
     * @param email the authenticated user's email (from the JWT subject)
     * @return the user's profile as a {@link UserResponse} (no password)
     * @throws com.bothsann.authify.common.exception.ResourceNotFoundException if not found
     */
    UserResponse getCurrentUser(String email);

    /**
     * Updates the first and last name of the currently authenticated user.
     *
     * @param email   the authenticated user's email
     * @param request the new name values
     * @return the updated profile
     * @throws com.bothsann.authify.common.exception.ResourceNotFoundException if not found
     */
    UserResponse updateCurrentUser(String email, UpdateProfileRequest request);

    /**
     * Returns all registered users. Admin-only operation.
     *
     * @return list of all user profiles (no passwords)
     */
    List<UserResponse> getAllUsers();

    /**
     * Deletes a user by their UUID. Admin-only operation.
     *
     * @param id the UUID of the user to delete
     * @throws com.bothsann.authify.common.exception.ResourceNotFoundException if not found
     */
    void deleteUser(UUID id);
}
