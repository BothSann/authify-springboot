package com.bothsann.authify.passwordreset;

import com.bothsann.authify.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA repository for {@link PasswordResetToken} entities.
 */
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, UUID> {

    /**
     * Looks up a password reset token by its raw token string.
     *
     * <p>Called by {@code PasswordResetService} when a user submits a reset request.
     * Returns empty if the token doesn't exist (e.g., already used or never issued),
     * which the service treats as an invalid token.
     */
    Optional<PasswordResetToken> findByToken(String token);

    /**
     * Deletes all reset tokens belonging to a user.
     *
     * <p>Called before issuing a new reset token for the same user — ensures there
     * is at most one active reset token per user at any time, preventing a scenario
     * where an old token sent in a previous email could still be used.
     */
    void deleteByUser(User user);
}
