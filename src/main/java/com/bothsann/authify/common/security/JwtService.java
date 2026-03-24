package com.bothsann.authify.common.security;

import com.bothsann.authify.user.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Service responsible for all JWT operations: generating, validating, and parsing tokens.
 *
 * <h2>JJWT 0.12+ / 0.13 API note</h2>
 *
 * <p>Many online tutorials use the older JJWT 0.11.x API which looks like:
 * <pre>
 *   Jwts.builder().setClaims(...).setSubject(...).signWith(key, SignatureAlgorithm.HS256)
 *   Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody()
 * </pre>
 *
 * <p>This project uses JJWT 0.13.0. The modern API is:
 * <pre>
 *   Jwts.builder().claims(...).subject(...).signWith(key, Jwts.SIG.HS256)
 *   Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload()
 * </pre>
 *
 * <p>Key differences:
 * <ul>
 *   <li>Setter-style methods ({@code setSubject}, {@code setIssuedAt}) are replaced
 *       by builder-style ({@code subject}, {@code issuedAt})</li>
 *   <li>{@code SignatureAlgorithm.HS256} is removed; use {@code Jwts.SIG.HS256}</li>
 *   <li>{@code parseClaimsJws} is replaced by {@code parseSignedClaims}</li>
 *   <li>{@code getBody()} is replaced by {@code getPayload()}</li>
 *   <li>{@code parserBuilder()} is replaced by {@code parser()}</li>
 * </ul>
 *
 * <h2>Secret key format</h2>
 *
 * <p>The {@code JWT_SECRET_KEY} in your {@code .env} file must be a Base64-encoded
 * string representing at least 32 bytes (256 bits). You can generate one with:
 * <pre>openssl rand -base64 32</pre>
 */
@Service
@Slf4j
public class JwtService {

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.access-token-expiration}")
    private long accessTokenExpiration;

    @Value("${application.security.jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    // -------------------------------------------------------------------------
    // Token generation
    // -------------------------------------------------------------------------

    /**
     * Generates a signed access token for the given user.
     *
     * <p>Access tokens include extra claims (email, role) so downstream services
     * can read user identity from the token without a database lookup.
     */
    public String generateAccessToken(UserDetails userDetails) {
        Map<String, Object> extraClaims = new HashMap<>();

        // Cast to our concrete User type to access typed fields.
        // UserDetails only exposes getUsername() and getAuthorities().
        if (userDetails instanceof User user) {
            extraClaims.put("email", user.getEmail());
            extraClaims.put("role", user.getRole().name());
        }

        log.debug("Generating access token for user: {}", userDetails.getUsername());
        return buildToken(extraClaims, userDetails, accessTokenExpiration);
    }

    /**
     * Generates a signed refresh token for the given user.
     *
     * <p>Refresh tokens carry no extra claims beyond the subject (email) and expiry.
     * They are only used to obtain a new access token — never to access resources
     * directly.
     */
    public String generateRefreshToken(UserDetails userDetails) {
        log.debug("Generating refresh token for user: {}", userDetails.getUsername());
        return buildToken(new HashMap<>(), userDetails, refreshTokenExpiration);
    }

    // -------------------------------------------------------------------------
    // Claim extraction
    // -------------------------------------------------------------------------

    /**
     * Extracts the subject (email) from a token.
     *
     * <p>Used by {@link JwtAuthFilter} to identify which user a request token belongs to.
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extracts an arbitrary claim from a token using a resolver function.
     *
     * <p>This generic method is the foundation all other extraction methods build on.
     * Example usage:
     * <pre>
     *   String email = extractClaim(token, claims -> claims.get("email", String.class));
     *   Date expiry = extractClaim(token, Claims::getExpiration);
     * </pre>
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // -------------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------------

    /**
     * Returns {@code true} if the token's subject matches the user's username
     * AND the token has not expired.
     *
     * <p>Called by {@link JwtAuthFilter} after loading the user from the database
     * to confirm the token is legitimate for that user.
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    /**
     * Returns {@code true} if the token's expiration timestamp is in the past.
     */
    public boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Builds and signs a JWT with the given claims, subject, and expiration.
     *
     * <p>This is the single point of token construction — both access and refresh
     * tokens are built here to avoid code duplication.
     */
    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails,
                              long expiration) {
        return Jwts.builder()
                .claims(extraClaims)                        // custom claims (email, role)
                .subject(userDetails.getUsername())         // "sub" claim = email
                .issuedAt(new Date())                       // "iat" claim
                .expiration(new Date(System.currentTimeMillis() + expiration))  // "exp" claim
                // Jwts.SIG.HS256 is the 0.12+ way — SignatureAlgorithm.HS256 was removed
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    /**
     * Parses and verifies a token, returning all its claims.
     *
     * <p>JJWT 0.12+ API: {@code parseSignedClaims(...).getPayload()} replaces the
     * older {@code parseClaimsJws(...).getBody()}.
     *
     * <p>Throws a {@link io.jsonwebtoken.JwtException} subclass if the token is
     * malformed, the signature is invalid, or the token is expired. The caller
     * ({@link JwtAuthFilter}) catches this and lets the filter chain continue.
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())   // provide the key to verify the signature
                .build()
                .parseSignedClaims(token)      // parse + verify
                .getPayload();                 // .getBody() in old API
    }

    /**
     * Decodes the Base64 secret key from config and converts it to a {@link SecretKey}
     * suitable for HMAC-SHA signing.
     *
     * <p>The key is derived fresh on each call — it is cheap and stateless.
     */
    private SecretKey getSigningKey() {
        // Decoders.BASE64 handles standard Base64 (not URL-safe).
        // The raw bytes must be at least 32 bytes (256 bits) for HS256.
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
