package com.bothsann.authify.common.email;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

/**
 * Gmail SMTP implementation of {@link EmailService}.
 *
 * <h2>Graceful no-op when email is not configured</h2>
 *
 * <p>If {@code MAIL_USERNAME} is not set in the environment (e.g., during local
 * development without Gmail credentials), this service detects the empty value and
 * logs a warning instead of sending. The application starts and runs normally — only
 * the actual email delivery is skipped.
 *
 * <p>To enable real email sending, add to your {@code .env} file:
 * <pre>
 *   MAIL_USERNAME=your-gmail@gmail.com
 *   MAIL_PASSWORD=your-16-char-app-password
 * </pre>
 *
 * <p>Note: use a Gmail App Password (not your account password). Generate one at:
 * Google Account → Security → 2-Step Verification → App passwords.
 *
 * <h2>Why {@code MailException} is caught without rethrowing</h2>
 *
 * <p>SMTP failures (wrong credentials, network timeout, Gmail quota exceeded) should
 * not cause the password reset endpoint to return 500. The token is already in the
 * database — the user can retry the forgot-password request. Logging the error is
 * sufficient for operator visibility.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;

    /**
     * The Gmail address used as the sender. Empty string if {@code MAIL_USERNAME} is
     * not set in the environment — used to detect unconfigured state.
     */
    @Value("${spring.mail.username:}")
    private String senderEmail;

    @Override
    public void sendPasswordResetEmail(String to, String resetLink) {
        // Skip sending if mail credentials are not configured
        if (senderEmail == null || senderEmail.isBlank()) {
            log.warn("Mail not configured (MAIL_USERNAME is empty) — "
                    + "skipping password reset email to: {}", to);
            log.info("Reset link (would have been emailed): {}", resetLink);
            return;
        }

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(senderEmail);
            message.setTo(to);
            message.setSubject("Authify — Password Reset Request");
            message.setText(
                    "Hello,\n\n"
                    + "You requested a password reset for your Authify account.\n\n"
                    + "Click the link below to set a new password (valid for 15 minutes):\n"
                    + resetLink + "\n\n"
                    + "If you did not request this, you can safely ignore this email.\n\n"
                    + "— The Authify Team"
            );

            mailSender.send(message);
            log.info("Password reset email sent to: {}", to);

        } catch (MailException e) {
            // Log the failure but don't propagate — SMTP errors should not cause 500 responses
            log.error("Failed to send password reset email to {}: {}", to, e.getMessage());
        }
    }
}
