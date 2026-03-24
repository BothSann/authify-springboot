package com.bothsann.authify.common.security;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Master Spring Security configuration for the Authify application.
 *
 * <p>This class wires together all the security components built in Steps 5–9
 * into a single {@link SecurityFilterChain} that governs every HTTP request.
 *
 * <h2>Why CSRF is disabled</h2>
 *
 * <p>CSRF (Cross-Site Request Forgery) protection works by embedding a secret token
 * in HTML forms or cookies that the browser sends back with every state-changing request.
 * The server checks this token to confirm the request originated from its own UI, not
 * from a malicious third-party site that tricked the user's browser into making a request.
 *
 * <p>CSRF attacks exploit the browser's automatic inclusion of session cookies. In a
 * stateless REST API with JWT Bearer tokens:
 * <ul>
 *   <li>There is no session cookie — the server never creates an {@code HttpSession}</li>
 *   <li>The JWT is sent in the {@code Authorization} header, which browsers do NOT send
 *       automatically (unlike cookies)</li>
 *   <li>A malicious site cannot read the JWT from another domain (same-origin policy)</li>
 * </ul>
 *
 * <p>Because none of the CSRF attack vectors apply to stateless JWT APIs, CSRF protection
 * is unnecessary and is disabled here.
 *
 * <h2>Why session management is set to STATELESS</h2>
 *
 * <p>By default, Spring Security creates an {@code HttpSession} on the first request and
 * stores the {@code Authentication} object there. On subsequent requests, it reads the
 * session ID from the cookie to restore authentication — this is stateful authentication.
 *
 * <p>With JWT Bearer tokens, we validate the token on every request. No session is needed
 * because the token itself carries the user identity. Setting {@code STATELESS} tells
 * Spring Security:
 * <ul>
 *   <li>Never create an {@code HttpSession}</li>
 *   <li>Never read an existing session to restore authentication</li>
 *   <li>Each request must authenticate itself from scratch (via the JWT)</li>
 * </ul>
 *
 * <h2>What {@code AuthenticationEntryPoint} does</h2>
 *
 * <p>When an unauthenticated request reaches a protected route, Spring Security calls
 * the configured {@code AuthenticationEntryPoint}. By default, it returns an HTML
 * redirect to a login page ({@code /login?error}). For a REST API, a redirect is
 * useless — clients need a JSON 401 response.
 *
 * <p>Our entry point writes a JSON body directly to the response with HTTP 401.
 * Note: {@code GlobalExceptionHandler} ({@code @RestControllerAdvice}) does NOT
 * handle filter-level rejections — the filter chain runs before the DispatcherServlet,
 * so the exception handler is never invoked. The entry point must write the response
 * itself.
 *
 * <h2>What {@code AccessDeniedHandler} does</h2>
 *
 * <p>When an authenticated user tries to access a route they don't have the required
 * role for, Spring Security calls the {@code AccessDeniedHandler}. This is distinct
 * from {@code AuthenticationEntryPoint}:
 * <ul>
 *   <li>{@code AuthenticationEntryPoint} → unauthenticated request → 401</li>
 *   <li>{@code AccessDeniedHandler} → authenticated but wrong role → 403</li>
 * </ul>
 *
 * <h2>Why {@code JwtAuthFilter} runs before {@code UsernamePasswordAuthenticationFilter}</h2>
 *
 * <p>{@code UsernamePasswordAuthenticationFilter} processes form-based login requests
 * (POST to {@code /login} with HTML form fields). Our API has no form-based login —
 * all authentication is via JWT. Running {@code JwtAuthFilter} first populates the
 * {@code SecurityContext} from the token, so Spring's built-in filter finds the
 * context already populated and skips its own processing.
 *
 * <h2>Why {@code @EnableMethodSecurity} is included</h2>
 *
 * <p>This annotation activates method-level security annotations ({@code @PreAuthorize},
 * {@code @PostAuthorize}, {@code @Secured}). It is not used in this file, but it enables
 * fine-grained access control on individual controller methods in later steps — for
 * example:
 * <pre>
 *   &#64;PreAuthorize("hasRole('ADMIN') or #id == principal.id")
 *   public UserResponse getUser(UUID id) { ... }
 * </pre>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final CustomAuthenticationProvider customAuthenticationProvider;

    @Value("${application.frontend-url}")
    private String frontendUrl;

    /**
     * Builds the main security filter chain that applies to all HTTP requests.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // CSRF disabled — stateless REST API with JWT Bearer tokens (see Javadoc above)
                .csrf(AbstractHttpConfigurer::disable)

                // CORS — allow requests only from the configured frontend URL
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // No HttpSession ever created — each request authenticates via its JWT
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Authorization rules — order matters; more specific rules must come first
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/api/auth/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/auth/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/admin/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/admin/**").hasRole("ADMIN")
                        // All other routes require an authenticated user (any role)
                        .anyRequest().authenticated()
                )

                // Register our custom provider (bypasses the default DaoAuthenticationProvider)
                .authenticationProvider(customAuthenticationProvider)

                // Run JwtAuthFilter before Spring's form-login filter (see Javadoc above)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)

                .exceptionHandling(ex -> ex
                        // 401 for unauthenticated requests to protected routes
                        // Must write JSON here — @RestControllerAdvice does not cover filter-level errors
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            response.getWriter().write(
                                    "{\"status\":401,\"error\":\"Unauthorized\",\"message\":\"Authentication required\"}"
                            );
                        })
                        // 403 for authenticated users accessing routes above their role
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            response.getWriter().write(
                                    "{\"status\":403,\"error\":\"Forbidden\",\"message\":\"Insufficient permissions\"}"
                            );
                        })
                );

        return http.build();
    }

    /**
     * Configures CORS — which frontend origins, HTTP methods, and headers are allowed.
     *
     * <p>CORS (Cross-Origin Resource Sharing) is enforced by the browser when a web
     * page makes an HTTP request to a different domain than the one that served the page.
     * Without this configuration, the browser would block all cross-origin API calls
     * from the frontend.
     *
     * <p>Key settings:
     * <ul>
     *   <li>Allowed origins: only {@code FRONTEND_URL} from {@code .env} — prevents
     *       random third-party sites from calling the API via browser</li>
     *   <li>Allow credentials: {@code false} — we don't use cookies; credentials travel
     *       via the Authorization header instead</li>
     *   <li>Allowed headers: only what we need — {@code Authorization} (the JWT) and
     *       {@code Content-Type} (JSON request bodies)</li>
     * </ul>
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of(frontendUrl));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        // false because we use Authorization header, not cookies
        configuration.setAllowCredentials(false);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Apply this CORS policy to every endpoint
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
