package com.bothsann.authify.auth.service.impl;

import com.bothsann.authify.auth.dto.AuthResponse;
import com.bothsann.authify.auth.dto.LoginRequest;
import com.bothsann.authify.auth.dto.RefreshTokenRequest;
import com.bothsann.authify.auth.dto.RegisterRequest;
import com.bothsann.authify.auth.service.AuthService;
import com.bothsann.authify.exception.ResourceNotFoundException;
import com.bothsann.authify.exception.UserAlreadyExistsException;
import com.bothsann.authify.security.JwtService;
import com.bothsann.authify.token.entity.RefreshToken;
import com.bothsann.authify.token.service.RefreshTokenService;
import com.bothsann.authify.user.entity.Role;
import com.bothsann.authify.user.entity.User;
import com.bothsann.authify.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Default implementation of {@link AuthService}.
 *
 * <h2>register flow</h2>
 * <ol>
 *   <li>Check uniqueness → throw {@code UserAlreadyExistsException} if duplicate</li>
 *   <li>BCrypt the raw password</li>
 *   <li>Persist the new {@code User} with role = USER</li>
 *   <li>Generate access + refresh token pair</li>
 * </ol>
 *
 * <h2>login flow</h2>
 * <ol>
 *   <li>Call {@code authenticationManager.authenticate()} — routes through
 *       {@code ProviderManager} → {@code CustomAuthenticationProvider}</li>
 *   <li>If invalid → {@code BadCredentialsException} propagates up to
 *       {@code GlobalExceptionHandler} → 401</li>
 *   <li>If valid → load the {@code User} entity and generate a token pair</li>
 * </ol>
 *
 * <h2>refreshToken flow</h2>
 * <ol>
 *   <li>Find the refresh token in the DB</li>
 *   <li>Verify it hasn't expired (deletes + throws if it has)</li>
 *   <li>Rotate: delete old token, persist new one</li>
 *   <li>Generate a new access token for the token's user</li>
 * </ol>
 *
 * <h2>logout flow</h2>
 * <ol>
 *   <li>Find the refresh token in the DB</li>
 *   <li>Delete it — any subsequent refresh attempt returns 401</li>
 * </ol>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    @Override
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        // Fail fast if the email is already taken
        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new UserAlreadyExistsException(
                    "An account with email '" + request.email() + "' already exists.");
        }

        // Hash the raw password before persisting — never store plaintext
        User user = User.builder()
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .firstName(request.firstName())
                .lastName(request.lastName())
                .role(Role.USER)
                .enabled(true)
                .build();

        userRepository.save(user);
        log.info("New user registered: {}", user.getEmail());

        String accessToken = jwtService.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

        return new AuthResponse(accessToken, refreshToken.getToken());
    }

    @Override
    public AuthResponse login(LoginRequest request) {
        // Delegate credential verification to CustomAuthenticationProvider via ProviderManager.
        // This call throws BadCredentialsException if email/password are wrong —
        // that exception propagates to GlobalExceptionHandler → 401.
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password())
        );

        // At this point authentication succeeded — load the full User entity for token generation
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "User not found: " + request.email()));

        log.info("User logged in: {}", user.getEmail());

        String accessToken = jwtService.generateAccessToken(user);
        // createRefreshToken handles deleting any existing token for this user first
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

        return new AuthResponse(accessToken, refreshToken.getToken());
    }

    @Override
    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        // Throws InvalidTokenException if token is not in the DB
        RefreshToken refreshToken = refreshTokenService.findByToken(request.refreshToken());

        // Throws TokenExpiredException (and deletes the token) if it's past its expiresAt
        refreshTokenService.verifyExpiration(refreshToken);

        // Rotate: delete old token and issue a new one for the same user
        RefreshToken newRefreshToken = refreshTokenService.rotateRefreshToken(refreshToken);

        // Generate a new access token for the user attached to the refresh token
        String newAccessToken = jwtService.generateAccessToken(newRefreshToken.getUser());

        log.debug("Token refreshed for user: {}", newRefreshToken.getUser().getEmail());

        return new AuthResponse(newAccessToken, newRefreshToken.getToken());
    }

    @Override
    @Transactional
    public void logout(RefreshTokenRequest request) {
        // Throws InvalidTokenException if token is not found — prevents silent no-ops
        RefreshToken refreshToken = refreshTokenService.findByToken(request.refreshToken());

        refreshTokenService.deleteByUser(refreshToken.getUser());
        log.info("User logged out: {}", refreshToken.getUser().getEmail());
    }
}
