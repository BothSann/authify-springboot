package com.bothsann.authify.common.security;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT authentication filter that intercepts every HTTP request exactly once.
 *
 * <h2>Why {@code OncePerRequestFilter}?</h2>
 *
 * <p>In a Servlet container, a filter can be invoked more than once per logical
 * request if the request is internally forwarded (e.g., Spring MVC's
 * {@code RequestDispatcher.forward()}). {@code OncePerRequestFilter} uses a
 * request-scoped flag to guarantee the filter body runs exactly once per original
 * request, regardless of how many times the filter is in the chain.
 *
 * <h2>What this filter does</h2>
 *
 * <ol>
 *   <li>Reads the {@code Authorization} header looking for a Bearer token</li>
 *   <li>If no Bearer token is present, passes the request through unchanged —
 *       public routes ({@code /api/auth/**}) will be allowed by the
 *       {@link SecurityConfig} route rules; protected routes will be rejected
 *       by the {@code AuthenticationEntryPoint}</li>
 *   <li>If a Bearer token IS present, validates it and — if valid — writes an
 *       {@code Authentication} object into the {@code SecurityContext} so that
 *       downstream code can identify the caller via
 *       {@code SecurityContextHolder.getContext().getAuthentication()}</li>
 * </ol>
 *
 * <h2>Why this filter runs BEFORE {@code UsernamePasswordAuthenticationFilter}</h2>
 *
 * <p>{@code UsernamePasswordAuthenticationFilter} handles form-based logins
 * (POST to {@code /login} with username/password form params). In our stateless
 * REST API, no form-based login exists — all authentication is via JWT Bearer tokens.
 * Running our filter first means the {@code SecurityContext} is populated before
 * Spring Security's own filter tries to authenticate, so Spring's filter sees an
 * already-authenticated request and does nothing.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    // Inject the interface, not the implementation — keeps coupling loose.
    // Spring resolves this to CustomUserDetailsService via the bean in ApplicationConfig.
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        // If there is no Authorization header or it doesn't start with "Bearer ",
        // skip JWT processing entirely. The SecurityFilterChain route rules will
        // decide whether the request is allowed (public route) or rejected (401).
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Strip the "Bearer " prefix (7 characters) to get the raw JWT string
        final String jwt = authHeader.substring(7);
        final String userEmail;

        try {
            userEmail = jwtService.extractUsername(jwt);
        } catch (JwtException e) {
            // The token is malformed, has an invalid signature, or is expired.
            // We catch silently here instead of throwing — throwing from a filter
            // results in a 500 Internal Server Error rather than a clean 401.
            // By passing the request through, the SecurityContext remains empty,
            // and the AuthenticationEntryPoint will return a proper 401 JSON response.
            log.debug("Invalid JWT token: {}", e.getMessage());
            filterChain.doFilter(request, response);
            return;
        }

        // Only set authentication if:
        // 1. We successfully extracted a username from the token
        // 2. No authentication is already set in the SecurityContext for this request
        //    (prevents redundant DB lookups on forwarded requests)
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);

            if (jwtService.isTokenValid(jwt, userDetails)) {
                // Create a fully authenticated token.
                // Credentials are null — we already verified via JWT; no need to keep
                // the token in memory as a credential.
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                // Attach request details (IP address, session ID) to the auth token.
                // This enriches the Authentication object for auditing and logging.
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Write the authenticated token into the SecurityContext.
                // After this line, the request is considered authenticated for all
                // downstream processing (controllers, method security, etc.)
                SecurityContextHolder.getContext().setAuthentication(authToken);

                log.debug("Set authentication for user: {}", userEmail);
            }
        }

        // Always call filterChain.doFilter() to pass the request to the next filter.
        // This must be called even if authentication failed — the security rules
        // further down the chain will handle the rejection.
        filterChain.doFilter(request, response);
    }
}
