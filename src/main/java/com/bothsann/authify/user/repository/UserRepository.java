package com.bothsann.authify.user.repository;

import com.bothsann.authify.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA repository for {@link User} entities.
 *
 * <p>Extending {@code JpaRepository<User, UUID>} gives us all standard CRUD operations
 * ({@code save}, {@code findById}, {@code findAll}, {@code delete}, etc.) with zero
 * boilerplate. Spring generates the implementation at startup using dynamic proxies.
 *
 * <p>{@code findByEmail} is a "derived query" method — Spring Data JPA parses the
 * method name and automatically generates the SQL:
 * {@code SELECT * FROM users WHERE email = ?}. No {@code @Query} annotation needed.
 */
public interface UserRepository extends JpaRepository<User, UUID> {

    /**
     * Looks up a user by their email address.
     *
     * <p>Used by {@code CustomUserDetailsService} during authentication, and by
     * {@code AuthService} during registration to check for duplicate emails.
     *
     * @param email the email address to search for
     * @return an {@code Optional} containing the user, or empty if not found
     */
    Optional<User> findByEmail(String email);
}
