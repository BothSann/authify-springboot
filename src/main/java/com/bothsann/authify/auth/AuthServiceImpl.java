package com.bothsann.authify.auth;

import com.bothsann.authify.auth.dto.AuthResponse;
import com.bothsann.authify.auth.dto.LoginRequest;
import com.bothsann.authify.auth.dto.RefreshTokenRequest;
import com.bothsann.authify.auth.dto.RegisterRequest;
import com.bothsann.authify.common.exception.ResourceNotFoundException;
import com.bothsann.authify.common.exception.UserAlreadyExistsException;
import com.bothsann.authify.common.security.JwtService;
import com.bothsann.authify.token.RefreshToken;
import com.bothsann.authify.token.RefreshTokenService;
import com.bothsann.authify.user.Role;
import com.bothsann.authify.user.User;
import com.bothsann.authify.user.UserRepository;
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
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new UserAlreadyExistsException(
                    "An account with email '" + request.getEmail() + "' already exists.");
        }

        // Hash the raw password before persisting — never store plaintext
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .role(Role.USER)
                .enabled(true)
                .build();

        userRepository.save(user);
        log.info("New user registered: {}", user.getEmail());

        String accessToken = jwtService.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .build();
    }

    @Override
    public AuthResponse login(LoginRequest request) {
        // Delegate credential verification to CustomAuthenticationProvider via ProviderManager.
        // This call throws BadCredentialsException if email/password are wrong —
        // that exception propagates to GlobalExceptionHandler → 401.
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        // At this point authentication succeeded — load the full User entity for token generation
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "User not found: " + request.getEmail()));

        log.info("User logged in: {}", user.getEmail());

        String accessToken = jwtService.generateAccessToken(user);
        // createRefreshToken handles deleting any existing token for this user first
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .build();
    }

    @Override
    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        // Throws InvalidTokenException if token is not in the DB
        RefreshToken refreshToken = refreshTokenService.findByToken(request.getRefreshToken());

        // Throws TokenExpiredException (and deletes the token) if it's past its expiresAt
        refreshTokenService.verifyExpiration(refreshToken);

        // Rotate: delete old token and issue a new one for the same user
        RefreshToken newRefreshToken = refreshTokenService.rotateRefreshToken(refreshToken);

        // Generate a new access token for the user attached to the refresh token
        String newAccessToken = jwtService.generateAccessToken(newRefreshToken.getUser());

        log.debug("Token refreshed for user: {}", newRefreshToken.getUser().getEmail());

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken.getToken())
                .build();
    }

    @Override
    @Transactional
    public void logout(RefreshTokenRequest request) {
        // Throws InvalidTokenException if token is not found — prevents silent no-ops
        RefreshToken refreshToken = refreshTokenService.findByToken(request.getRefreshToken());

        refreshTokenService.deleteByUser(refreshToken.getUser());
        log.info("User logged out: {}", refreshToken.getUser().getEmail());
    }
}
