package com.bothsann.authify.token;

import com.bothsann.authify.common.exception.InvalidTokenException;
import com.bothsann.authify.common.exception.ResourceNotFoundException;
import com.bothsann.authify.common.exception.TokenExpiredException;
import com.bothsann.authify.user.User;
import com.bothsann.authify.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/**
 * Default implementation of {@link RefreshTokenService}.
 *
 * <p>Refresh tokens are stored in the {@code refresh_tokens} table as opaque UUID strings.
 * The expiry is computed server-side and stored explicitly — the client never needs to
 * decode a JWT to know when a refresh token expires.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    /**
     * How long (in milliseconds) a refresh token is valid. Injected from
     * {@code application.security.jwt.refresh-token-expiration} (default: 7 days).
     */
    @Value("${application.security.jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    /**
     * {@inheritDoc}
     *
     * <p>Deletes any existing refresh token for the user before creating a new one.
     * This enforces single-session semantics: logging in on a second device revokes
     * the session on the first.
     */
    @Override
    @Transactional
    public RefreshToken createRefreshToken(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + userId));

        // Revoke any existing token for this user — one active session per user
        refreshTokenRepository.findByUser(user)
                .ifPresent(existing -> {
                    refreshTokenRepository.delete(existing);
                    log.debug("Deleted existing refresh token for user: {}", user.getEmail());
                });

        RefreshToken refreshToken = RefreshToken.builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                // Convert milliseconds to a LocalDateTime expiry
                .expiresAt(LocalDateTime.now().plus(refreshTokenExpiration, ChronoUnit.MILLIS))
                .build();

        RefreshToken saved = refreshTokenRepository.save(refreshToken);
        log.debug("Created refresh token for user: {}", user.getEmail());
        return saved;
    }

    /**
     * {@inheritDoc}
     *
     * <p>If the token is expired, it is deleted from the database before throwing.
     * This ensures stale tokens don't accumulate and that any retry with the same
     * token also fails with the same error.
     */
    @Override
    @Transactional
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            refreshTokenRepository.delete(token);
            log.warn("Expired refresh token deleted for user: {}", token.getUser().getEmail());
            throw new TokenExpiredException("Refresh token has expired. Please log in again.");
        }
        return token;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public RefreshToken findByToken(String token) {
        return refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new InvalidTokenException(
                        "Refresh token not found or has been revoked."));
    }

    /**
     * {@inheritDoc}
     *
     * <p>Marked {@code @Transactional} because Spring Data's derived delete queries
     * require an active transaction to execute correctly.
     */
    @Override
    @Transactional
    public void deleteByUser(User user) {
        refreshTokenRepository.deleteByUser(user);
        log.debug("Revoked refresh token for user: {}", user.getEmail());
    }

    /**
     * {@inheritDoc}
     *
     * <p>The old token is deleted FIRST, then a new one is created for the same user.
     * We do NOT call {@link #createRefreshToken(UUID)} here because that method also
     * calls {@code findByUser().ifPresent(delete)} — which would be a redundant lookup
     * after we already deleted the old token. Instead we build and save the new token
     * directly to avoid the double-delete path.
     */
    @Override
    @Transactional
    public RefreshToken rotateRefreshToken(RefreshToken old) {
        User user = old.getUser();

        // Delete old token
        refreshTokenRepository.delete(old);
        log.debug("Rotated refresh token for user: {}", user.getEmail());

        // Build and save the replacement directly (skip the findByUser check in createRefreshToken)
        RefreshToken newToken = RefreshToken.builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                .expiresAt(LocalDateTime.now().plus(refreshTokenExpiration, ChronoUnit.MILLIS))
                .build();

        return refreshTokenRepository.save(newToken);
    }
}
