package com.bothsann.authify.auth;

import com.bothsann.authify.auth.dto.AuthResponse;
import com.bothsann.authify.auth.dto.LoginRequest;
import com.bothsann.authify.auth.dto.RefreshTokenRequest;
import com.bothsann.authify.auth.dto.RegisterRequest;

/**
 * Core authentication operations: register, login, token refresh, and logout.
 *
 * <p>This interface is implemented by {@link AuthServiceImpl}. Defining it as an
 * interface allows {@link AuthController} to depend on the abstraction rather than the
 * concrete class — making each piece independently testable and swappable.
 */
public interface AuthService {

    /**
     * Registers a new user, hashes the password, persists the account, and returns
     * a fresh access + refresh token pair.
     *
     * @param request validated registration data
     * @return a token pair for the newly created user
     * @throws com.bothsann.authify.common.exception.UserAlreadyExistsException if the email is taken
     */
    AuthResponse register(RegisterRequest request);

    /**
     * Authenticates a user with email and password and returns a fresh token pair.
     *
     * <p>Delegates credential verification to {@code AuthenticationManager}, which routes
     * through {@code CustomAuthenticationProvider}.
     *
     * @param request validated login credentials
     * @return a token pair for the authenticated user
     * @throws org.springframework.security.authentication.BadCredentialsException if credentials are wrong
     */
    AuthResponse login(LoginRequest request);

    /**
     * Validates the provided refresh token, rotates it (issues a new one), and returns
     * a new access + refresh token pair.
     *
     * @param request the current refresh token
     * @return a new token pair
     * @throws com.bothsann.authify.common.exception.InvalidTokenException  if the token is not found
     * @throws com.bothsann.authify.common.exception.TokenExpiredException if the token has expired
     */
    AuthResponse refreshToken(RefreshTokenRequest request);

    /**
     * Revokes the provided refresh token, effectively ending the user's session.
     *
     * <p>After logout, any attempt to use the same refresh token returns 401. The
     * client should also discard the access token locally (it will expire naturally
     * after 15 minutes).
     *
     * @param request the refresh token to revoke
     * @throws com.bothsann.authify.common.exception.InvalidTokenException if the token is not found
     */
    void logout(RefreshTokenRequest request);
}
