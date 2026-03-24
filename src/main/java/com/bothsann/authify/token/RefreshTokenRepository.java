package com.bothsann.authify.token;

import com.bothsann.authify.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA repository for {@link RefreshToken} entities.
 *
 * <p>All three methods here are "derived query" methods — Spring Data generates
 * the SQL from the method name. No {@code @Query} annotations are needed.
 */
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    /**
     * Looks up a refresh token by its raw token string.
     *
     * <p>Called by {@code RefreshTokenService.findByToken()} when a client sends
     * a refresh request. Returns empty if the token doesn't exist (e.g., already
     * deleted on logout), which the service treats as an invalid token.
     */
    Optional<RefreshToken> findByToken(String token);

    /**
     * Looks up a user's existing refresh token.
     *
     * <p>Used in {@code RefreshTokenService.createRefreshToken()} to check whether
     * the user already has a token before issuing a new one. If one exists,
     * we delete it first to enforce the single-session constraint.
     */
    Optional<RefreshToken> findByUser(User user);

    /**
     * Deletes all refresh tokens belonging to a user.
     *
     * <p>Called on logout. After this, any refresh token the client holds becomes
     * immediately invalid — even if it hasn't expired yet. This is how we achieve
     * server-side revocation.
     *
     * <p>Spring Data generates: {@code DELETE FROM refresh_tokens WHERE user_id = ?}
     */
    void deleteByUser(User user);
}
