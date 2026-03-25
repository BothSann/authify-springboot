package com.bothsann.authify.token.entity;

import com.bothsann.authify.common.audit.Auditable;
import com.bothsann.authify.user.entity.User;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * JPA entity representing a refresh token stored in the database.
 *
 * <h2>Why store refresh tokens server-side?</h2>
 *
 * <p>Access tokens are stateless — they are self-contained JWTs that Spring Security
 * validates by checking the signature and expiry alone. No database lookup is needed.
 * This makes access tokens fast but also impossible to revoke: once issued, they are
 * valid until they expire (15 minutes in this project).
 *
 * <p>Refresh tokens solve the revocation problem. By persisting them in the database,
 * we can:
 * <ul>
 *   <li><strong>Revoke on logout:</strong> Delete the token row → the client's
 *       refresh token immediately becomes invalid, even if it hasn't expired yet.</li>
 *   <li><strong>Rotate tokens:</strong> On every refresh call, delete the old token
 *       and issue a new one. If a token is used twice, it signals a potential theft.</li>
 *   <li><strong>Enforce single-session:</strong> A user can only have one valid
 *       refresh token at a time (one row per user).</li>
 * </ul>
 *
 * <p>The trade-off: every refresh operation now requires a database read/write.
 * For a 7-day token, this is acceptable — clients only refresh every 15 minutes.
 *
 * <p>Extends {@link Auditable} to inherit automatic {@code createdAt} tracking.
 */
@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken extends Auditable {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // columnDefinition = "TEXT" allows tokens of any length.
    // VARCHAR(255) would work for most JWTs, but TEXT is safer since JWT size
    // can grow if you add more claims to the payload.
    @Column(unique = true, nullable = false, columnDefinition = "TEXT")
    private String token;

    // FetchType.LAZY = don't load the User from the DB unless user.getSomething()
    // is explicitly called. FetchType.EAGER (the default for @ManyToOne) would run
    // a JOIN on every RefreshToken query, even when you only need the token string.
    @ManyToOne(fetch = FetchType.LAZY)
    // @JoinColumn tells Hibernate the name of the foreign-key column in THIS table
    // that points to the users table. Without it, Hibernate would guess the name.
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // The expiry is stored explicitly so the server can check server-side expiry
    // without decoding the JWT. RefreshTokenService.verifyExpiration() reads this.
    @Column(nullable = false)
    private LocalDateTime expiresAt;
}
