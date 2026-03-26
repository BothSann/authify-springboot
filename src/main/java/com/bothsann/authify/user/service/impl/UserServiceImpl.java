package com.bothsann.authify.user.service.impl;

import com.bothsann.authify.exception.ResourceNotFoundException;
import com.bothsann.authify.user.dto.UpdateProfileRequest;
import com.bothsann.authify.user.dto.UserResponse;
import com.bothsann.authify.user.entity.User;
import com.bothsann.authify.user.repository.UserRepository;
import com.bothsann.authify.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Default implementation of {@link UserService}.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public UserResponse getCurrentUser(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + email));
        return UserResponse.from(user);
    }

    @Override
    @Transactional
    public UserResponse updateCurrentUser(String email, UpdateProfileRequest request) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + email));

        user.setFirstName(request.firstName());
        user.setLastName(request.lastName());

        User updated = userRepository.save(user);
        log.info("Profile updated for user: {}", email);
        return UserResponse.from(updated);
    }

    @Override
    public List<UserResponse> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(UserResponse::from)
                .toList();
    }

    @Override
    @Transactional
    public void deleteUser(UUID id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + id));
        userRepository.delete(user);
        log.info("User deleted: {}", user.getEmail());
    }
}
