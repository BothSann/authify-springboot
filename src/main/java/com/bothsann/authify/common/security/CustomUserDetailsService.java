package com.bothsann.authify.common.security;

import com.bothsann.authify.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Implements Spring Security's {@link UserDetailsService} to load user records
 * from the database during the authentication process.
 *
 * <h2>Why is the method named {@code loadUserByUsername} when we use email?</h2>
 *
 * <p>Spring Security was designed around the concept of a "username" — a unique string
 * that identifies a user. The {@link UserDetailsService} interface uses the term
 * "username" throughout, but the actual value can be anything: an email address, a
 * phone number, an account ID, etc. In Authify we identify users by email, so the
 * "username" in Spring Security's vocabulary maps directly to our {@code email} field.
 *
 * <p>When Spring Security needs to authenticate a user, it calls
 * {@code loadUserByUsername(email)}. Since our {@link com.bothsann.authify.user.User}
 * entity implements {@link UserDetails} directly, we can return it as-is — no wrapping
 * or adapting is needed.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Loads a user from the database by their email address.
     *
     * <p>The {@code username} parameter here is the value passed to
     * {@code UsernamePasswordAuthenticationToken} — in this application that is always
     * an email address.
     *
     * @param username the email address of the user to load
     * @return the {@link UserDetails} (our {@link com.bothsann.authify.user.User} entity)
     * @throws UsernameNotFoundException if no user with the given email exists
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("Loading user by email: {}", username);

        // findByEmail returns Optional<User>. If empty, throw UsernameNotFoundException
        // (Spring Security's standard signal that the user identity is unknown).
        return userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException(
                        "No user found with email: " + username
                ));
    }
}
