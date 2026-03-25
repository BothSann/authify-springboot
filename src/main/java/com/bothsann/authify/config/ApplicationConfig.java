package com.bothsann.authify.config;

import com.bothsann.authify.security.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Declares the core Spring Security beans used across the application.
 *
 * <p>This configuration class is intentionally separate from
 * {@link com.bothsann.authify.common.security.SecurityConfig} to avoid circular
 * dependencies. Specifically:
 * <ul>
 *   <li>{@code SecurityConfig} depends on {@code JwtAuthFilter} and
 *       {@code CustomAuthenticationProvider}</li>
 *   <li>{@code CustomAuthenticationProvider} depends on {@code PasswordEncoder} (from here)</li>
 *   <li>If {@code PasswordEncoder} were declared inside {@code SecurityConfig}, the
 *       dependency chain would form a cycle</li>
 * </ul>
 *
 * <h2>Why expose {@code AuthenticationManager} as a bean?</h2>
 *
 * <p>{@code AuthService} (Step 13) needs to manually trigger the authentication pipeline
 * on login. It does so by calling:
 * <pre>
 *   authenticationManager.authenticate(
 *       new UsernamePasswordAuthenticationToken(email, password)
 *   );
 * </pre>
 *
 * <p>Spring's {@code AuthenticationManager} is internally available during security
 * configuration, but it is NOT exposed as a bean by default. We expose it here so
 * {@code AuthService} can inject it with {@code @Autowired} / constructor injection.
 *
 * <p>The {@code AuthenticationConfiguration} parameter is provided by Spring Boot's
 * auto-configuration. Calling {@code config.getAuthenticationManager()} returns the
 * fully assembled manager that already includes our
 * {@link com.bothsann.authify.common.security.CustomAuthenticationProvider}.
 */
@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final CustomUserDetailsService customUserDetailsService;

    /**
     * Declares the password encoder used for hashing and verifying passwords.
     *
     * <p>BCrypt with strength 12 is used throughout:
     * <ul>
     *   <li>{@code AuthService} calls {@code passwordEncoder.encode(rawPassword)} before
     *       saving a new user</li>
     *   <li>{@code CustomAuthenticationProvider} calls
     *       {@code passwordEncoder.matches(raw, hashed)} to verify login credentials</li>
     * </ul>
     *
     * <p>Strength 12 means 2^12 = 4096 hash iterations. This is intentionally slow to
     * resist brute-force attacks. Each encode call takes ~300ms on modern hardware.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * Exposes the {@link AuthenticationManager} as a Spring bean.
     *
     * <p>Delegates to {@code AuthenticationConfiguration.getAuthenticationManager()},
     * which returns the manager that Spring Boot has assembled from all registered
     * {@link org.springframework.security.authentication.AuthenticationProvider}s —
     * including our {@link com.bothsann.authify.common.security.CustomAuthenticationProvider}.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
            throws Exception {
        return config.getAuthenticationManager();
    }
}
