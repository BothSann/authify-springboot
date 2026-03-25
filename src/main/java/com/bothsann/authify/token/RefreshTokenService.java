package com.bothsann.authify.token;

import com.bothsann.authify.user.User;

import java.util.UUID;

/**
 * Manages the full lifecycle of refresh tokens stored in the database.
 *
 * <h2>Why refresh tokens are stored server-side</h2>
 *
 * <p>Unlike access tokens (which are short-lived JWTs validated without a DB lookup),
 * refresh tokens must be stored in the database to support:
 * <ul>
 *   <li><strong>Revocation</strong> — logout deletes the token immediately; any attempt
 *       to use it after logout returns 401</li>
 *   <li><strong>Rotation</strong> — every successful refresh call issues a NEW token
 *       and invalidates the old one, limiting the reuse window to a single call</li>
 *   <li><strong>Single-session enforcement</strong> — only one refresh token exists
 *       per user at any given time; new login replaces the old one</li>
 * </ul>
 */
public interface RefreshTokenService {

    /**
     * Creates a new refresh token for the given user, deleting any existing one first
     * (enforces one active session per user).
     *
     * @param userId the ID of the user to create the token for
     * @return the persisted {@link RefreshToken}
     */
    RefreshToken createRefreshToken(UUID userId);

    /**
     * Checks whether the token has expired. If it has, the token is deleted from the
     * database before the exception is thrown — forcing the user to log in again.
     *
     * @param token the refresh token to verify
     * @return the same token if not expired
     * @throws com.bothsann.authify.common.exception.TokenExpiredException if expired
     */
    RefreshToken verifyExpiration(RefreshToken token);

    /**
     * Looks up a refresh token by its string value.
     *
     * @param token the raw token string
     * @return the matching {@link RefreshToken}
     * @throws com.bothsann.authify.common.exception.InvalidTokenException if not found
     */
    RefreshToken findByToken(String token);

    /**
     * Deletes all refresh tokens belonging to the given user.
     * Called on logout to immediately revoke the session.
     *
     * @param user the user whose tokens should be revoked
     */
    void deleteByUser(User user);

    /**
     * Rotates a refresh token: deletes the old token and creates a new one for the
     * same user. This is called on every successful {@code /api/auth/refresh} call
     * to limit the reuse window of any intercepted token.
     *
     * @param old the token to replace
     * @return the newly created {@link RefreshToken}
     */
    RefreshToken rotateRefreshToken(RefreshToken old);
}
