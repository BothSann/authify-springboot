package com.bothsann.authify.common.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Custom implementation of Spring Security's {@link AuthenticationProvider} that
 * validates email/password credentials against the database.
 *
 * <h2>Spring Security's default authentication flow (without this class)</h2>
 *
 * <p>Without any customization, Spring Boot auto-configures a
 * {@code DaoAuthenticationProvider}. This default provider:
 * <ol>
 *   <li>Calls {@code UserDetailsService.loadUserByUsername(username)}</li>
 *   <li>Checks the password with {@code PasswordEncoder.matches()}</li>
 *   <li>Checks account status ({@code isEnabled()}, {@code isAccountNonLocked()}, etc.)</li>
 *   <li>Returns a fully authenticated token on success</li>
 * </ol>
 *
 * <h2>Why implement a custom provider?</h2>
 *
 * <p>A custom {@code AuthenticationProvider} gives us full control over authentication
 * logic and enables features that the default provider doesn't support out of the box:
 * <ul>
 *   <li><strong>Logging:</strong> We can log every success and failure with context
 *       (IP address, timestamp, user ID) — critical for security auditing</li>
 *   <li><strong>Brute-force protection:</strong> Count failed attempts and lock accounts</li>
 *   <li><strong>Multi-factor authentication:</strong> Add a second validation step</li>
 *   <li><strong>Multiple auth strategies:</strong> Register multiple providers (e.g., one
 *       for password auth, one for API key auth, one for OAuth tokens)</li>
 *   <li><strong>Custom error messages:</strong> Return specific errors for specific
 *       failure types instead of a generic bad credentials message</li>
 * </ul>
 *
 * <h2>How {@code ProviderManager} uses this class</h2>
 *
 * <p>Spring Security's {@code AuthenticationManager} implementation is {@code ProviderManager}.
 * When {@code authenticationManager.authenticate(token)} is called, {@code ProviderManager}
 * iterates through its list of registered {@code AuthenticationProvider}s:
 * <ol>
 *   <li>For each provider, checks {@code provider.supports(token.getClass())}</li>
 *   <li>If {@code supports()} returns {@code true}, calls {@code provider.authenticate(token)}</li>
 *   <li>If authentication succeeds, returns the result immediately (short-circuits)</li>
 *   <li>If this provider throws {@code AuthenticationException}, tries the next provider</li>
 *   <li>If all providers fail or don't support the token, throws {@code ProviderNotFoundException}</li>
 * </ol>
 *
 * <h2>How this provider is registered</h2>
 *
 * <p>This class is annotated {@code @Component} so Spring creates it as a bean.
 * {@link com.bothsann.authify.common.security.SecurityConfig} injects it and registers
 * it in the {@code SecurityFilterChain} via {@code .authenticationProvider(this)}.
 * That registration adds this provider to the {@code ProviderManager}'s list.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    /**
     * Authenticates a username/password credential pair.
     *
     * <p>The {@code authentication} object here is always a
     * {@code UsernamePasswordAuthenticationToken} with:
     * <ul>
     *   <li>{@code getPrincipal()} → the email (String)</li>
     *   <li>{@code getCredentials()} → the raw password (String)</li>
     *   <li>Authorities empty — not yet authenticated</li>
     * </ul>
     *
     * <p>On success, returns a new {@code UsernamePasswordAuthenticationToken} with
     * {@code UserDetails} as the principal, {@code null} credentials (cleared for
     * security — no reason to keep the raw password in memory), and populated authorities.
     *
     * @throws BadCredentialsException if the password does not match
     * @throws org.springframework.security.core.userdetails.UsernameNotFoundException
     *         if no user exists with the given email (thrown by {@code loadUserByUsername})
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final String email = authentication.getName();
        final String rawPassword = authentication.getCredentials().toString();

        // Catch UsernameNotFoundException and convert it to BadCredentialsException.
        // This prevents user enumeration: both "email not found" and "wrong password"
        // return the same generic 401 with the same message — an attacker cannot tell
        // which one occurred. This mirrors what Spring's own DaoAuthenticationProvider
        // does internally via its hideUserNotFoundExceptions flag.
        UserDetails userDetails;
        try {
            userDetails = userDetailsService.loadUserByUsername(email);
        } catch (org.springframework.security.core.userdetails.UsernameNotFoundException ex) {
            log.warn("Login attempt for unregistered email: {}", email);
            throw new BadCredentialsException("Invalid email or password");
        }

        // BCrypt.matches() rehashes the raw password and compares to the stored hash.
        // This is intentionally slow (BCrypt strength 12) to resist brute-force.
        if (!passwordEncoder.matches(rawPassword, userDetails.getPassword())) {
            log.warn("Failed login attempt for email: {}", email);
            throw new BadCredentialsException("Invalid email or password");
        }

        log.info("Successful authentication for user: {}", email);

        // Return a fully authenticated token.
        // Credentials are null — the raw password is cleared immediately after
        // verification. There is no reason to keep it in memory.
        return new UsernamePasswordAuthenticationToken(
                userDetails,
                null,                          // cleared credentials
                userDetails.getAuthorities()   // populated authorities = authenticated
        );
    }

    /**
     * Declares which {@link Authentication} types this provider handles.
     *
     * <p>{@code ProviderManager} calls this before {@code authenticate()} to check if
     * this provider is relevant for the given token type. We only handle
     * {@code UsernamePasswordAuthenticationToken} — the standard token for
     * email/password logins.
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
