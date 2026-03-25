package com.bothsann.authify.passwordreset.entity;

import com.bothsann.authify.common.audit.Auditable;
import com.bothsann.authify.user.entity.User;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * JPA entity representing a single-use password reset token.
 *
 * <h2>Design decisions</h2>
 *
 * <p><strong>Why not just send a JWT for password reset?</strong>
 * A JWT is stateless — once issued, it can't be invalidated server-side. If a user
 * requests two password resets in quick succession (or if the first email was
 * intercepted), both tokens would remain valid until expiry. A database-backed token
 * can be marked {@code used = true} after the first successful reset, making any
 * subsequent use of the same token a rejected request.
 *
 * <p><strong>Why {@code used} flag instead of just deleting?</strong>
 * Keeping the row with {@code used = true} allows for audit logging — you can see
 * when and how many times a reset was requested. Deleting on use would lose that
 * history. The row can be cleaned up by a scheduled job later.
 *
 * <p><strong>Short expiry (15 minutes):</strong> Password reset emails are sensitive.
 * A short window minimizes the risk if the email is intercepted or the link is
 * shared accidentally.
 *
 * <p>Extends {@link Auditable} to inherit {@code createdAt} (useful for auditing
 * when the reset was requested).
 */
@Entity
@Table(name = "password_reset_tokens")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PasswordResetToken extends Auditable {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // VARCHAR(255) is sufficient here — reset tokens are shorter than JWTs
    // (typically a UUID or random hex string, not a full JWT).
    @Column(unique = true, nullable = false)
    private String token;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // Server-side expiry check — set to now() + 15 minutes when the token is created.
    @Column(nullable = false)
    private LocalDateTime expiresAt;

    // Once a reset is completed, this is set to true.
    // Any subsequent attempt to use the same token will be rejected.
    @Builder.Default
    private boolean used = false;
}
