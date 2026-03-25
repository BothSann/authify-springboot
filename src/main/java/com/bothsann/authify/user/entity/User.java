package com.bothsann.authify.user.entity;

import com.bothsann.authify.common.audit.Auditable;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * JPA entity representing a registered user account.
 *
 * <h2>Why does {@code User} implement {@code UserDetails}?</h2>
 *
 * <p>Spring Security's authentication pipeline operates on {@code UserDetails} objects,
 * not on domain entities directly. There are two common approaches:
 * <ol>
 *   <li><strong>Adapter pattern:</strong> Keep {@code User} as a plain entity and create
 *       a separate {@code UserPrincipal} wrapper that implements {@code UserDetails}.
 *       This is useful when you have multiple user types or want a strict boundary between
 *       the domain model and the security layer.</li>
 *   <li><strong>Direct implementation (this project):</strong> Have {@code User} itself
 *       implement {@code UserDetails}. Since Authify has exactly one user type and the
 *       domain model IS the security principal, this avoids extra indirection and keeps
 *       the codebase simpler. {@code CustomUserDetailsService} can return a {@code User}
 *       directly without wrapping it.</li>
 * </ol>
 *
 * <p>Extends {@link Auditable} to inherit automatic {@code createdAt}/{@code updatedAt}
 * timestamp management via Spring Data JPA Auditing.
 */
@Entity
@Table(name = "users")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User extends Auditable implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // Unique constraint is enforced at both the DB level (via @Column) and
    // application level (checked in AuthService before saving).
    @Column(unique = true, nullable = false)
    private String email;

    // Stored as a BCrypt hash — the plain-text password is never persisted.
    @Column(nullable = false)
    private String password;

    private String firstName;
    private String lastName;

    // EnumType.STRING stores "USER" or "ADMIN" as a readable string in the DB.
    // Using EnumType.ORDINAL (the default) would store 0 or 1 — fragile if the
    // enum order ever changes.
    @Enumerated(EnumType.STRING)
    private Role role;

    // Allows soft-disabling accounts without deleting them from the DB.
    @Builder.Default
    private boolean enabled = true;

    // -------------------------------------------------------------------------
    // UserDetails interface implementation
    // -------------------------------------------------------------------------

    /**
     * Returns the authorities (roles) granted to this user.
     *
     * <p>Spring Security's {@code hasRole("ADMIN")} check internally prepends "ROLE_",
     * so we must store authorities as "ROLE_USER" / "ROLE_ADMIN" here to match.
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // "ROLE_" prefix is required by Spring Security's hasRole() matcher.
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    /**
     * Spring Security uses this as the "username" for authentication.
     * We use email as the unique identifier instead of a display name.
     */
    @Override
    public String getUsername() {
        return email;
    }

    // The following three methods let Spring Security check account state.
    // We keep them all true for now — account locking/expiry is not in scope
    // for this project, but the methods are here if you want to add it later.

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // isEnabled() is inherited via @Getter from the `enabled` field above.
}
