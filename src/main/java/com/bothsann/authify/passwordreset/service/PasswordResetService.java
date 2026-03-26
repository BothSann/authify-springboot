package com.bothsann.authify.passwordreset.service;

import com.bothsann.authify.auth.dto.ForgotPasswordRequest;
import com.bothsann.authify.auth.dto.PasswordResetRequest;
import com.bothsann.authify.common.email.EmailService;
import com.bothsann.authify.exception.InvalidTokenException;
import com.bothsann.authify.exception.TokenExpiredException;
import com.bothsann.authify.passwordreset.entity.PasswordResetToken;
import com.bothsann.authify.passwordreset.repository.PasswordResetTokenRepository;
import com.bothsann.authify.user.entity.User;
import com.bothsann.authify.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

/**
 * Manages the two-step password reset flow: initiation and completion.
 *
 * <h2>Step 1 — Initiation ({@code POST /api/auth/forgot-password})</h2>
 * <ol>
 *   <li>Look up user by email. If not found, <strong>return silently</strong> — this
 *       prevents user enumeration: an attacker cannot tell which emails are registered
 *       by observing different responses.</li>
 *   <li>Delete any existing reset token for the user (clean state before issuing new one).</li>
 *   <li>Generate a random UUID token, persist it with a 15-minute expiry.</li>
 *   <li>Send the reset link via {@link EmailService}.</li>
 * </ol>
 *
 * <h2>Step 2 — Completion ({@code POST /api/auth/reset-password})</h2>
 * <ol>
 *   <li>Find the token — throw {@code InvalidTokenException} if not found.</li>
 *   <li>Reject if already used — throw {@code InvalidTokenException}.</li>
 *   <li>Reject if expired — throw {@code TokenExpiredException}.</li>
 *   <li>BCrypt the new password and save it to the user.</li>
 *   <li>Mark the token {@code used = true} (single-use enforcement).</li>
 * </ol>
 *
 * <h2>Why tokens must be single-use and time-limited</h2>
 *
 * <p>Unlike access JWTs (which are self-contained and can be validated without a DB),
 * reset tokens must be stored server-side so we can:
 * <ul>
 *   <li>Verify they were actually issued by us (not guessed)</li>
 *   <li>Mark them used to prevent replay attacks after the first successful reset</li>
 *   <li>Expire them after 15 minutes to limit the attack window</li>
 * </ul>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordResetService {

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    @Value("${application.frontend-url}")
    private String frontendUrl;

    /**
     * Initiates a password reset: creates a token and sends the reset link via email.
     *
     * <p>Returns silently (200 OK) even if the email is not registered — prevents
     * user enumeration. See class Javadoc for the security rationale.
     *
     * @param request contains the user's email address
     */
    @Transactional
    public void initiatePasswordReset(ForgotPasswordRequest request) {
        Optional<User> userOpt = userRepository.findByEmail(request.email());

        if (userOpt.isEmpty()) {
            // Silent no-op — do not reveal whether the email exists
            log.debug("Password reset requested for unknown email: {}", request.email());
            return;
        }

        User user = userOpt.get();

        // Clean up any existing token before issuing a new one
        passwordResetTokenRepository.deleteByUser(user);

        String tokenValue = UUID.randomUUID().toString();

        PasswordResetToken resetToken = PasswordResetToken.builder()
                .token(tokenValue)
                .user(user)
                .expiresAt(LocalDateTime.now().plusMinutes(15))
                .used(false)
                .build();

        passwordResetTokenRepository.save(resetToken);
        log.info("Password reset token created for user: {}", user.getEmail());

        // Link format: <frontend-url>/reset-password?token=<uuid>
        String resetLink = frontendUrl + "/reset-password?token=" + tokenValue;
        emailService.sendPasswordResetEmail(user.getEmail(), resetLink);
    }

    /**
     * Validates the reset token and updates the user's password.
     *
     * @param request contains the token string and the new plaintext password
     * @throws InvalidTokenException  if the token is not found or already used
     * @throws TokenExpiredException if the token's 15-minute window has passed
     */
    @Transactional
    public void resetPassword(PasswordResetRequest request) {
        PasswordResetToken resetToken = passwordResetTokenRepository
                .findByToken(request.token())
                .orElseThrow(() -> new InvalidTokenException(
                        "Invalid or unknown password reset token."));

        // Reject tokens that have already been consumed
        if (resetToken.isUsed()) {
            throw new InvalidTokenException("This password reset token has already been used.");
        }

        // Reject tokens whose 15-minute window has elapsed
        if (resetToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new TokenExpiredException(
                    "This password reset token has expired. Please request a new one.");
        }

        User user = resetToken.getUser();

        // BCrypt the new password before storing — never persist plaintext
        user.setPassword(passwordEncoder.encode(request.newPassword()));

        // Mark the token as used — prevents replay attacks
        resetToken.setUsed(true);

        userRepository.save(user);
        passwordResetTokenRepository.save(resetToken);

        log.info("Password reset completed for user: {}", user.getEmail());
    }
}
