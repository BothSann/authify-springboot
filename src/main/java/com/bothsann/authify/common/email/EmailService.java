package com.bothsann.authify.common.email;

/**
 * Abstraction for sending application emails.
 *
 * <p>Defining this as an interface rather than a concrete class means:
 * <ul>
 *   <li>{@code PasswordResetService} depends on the abstraction — not on JavaMailSender
 *       directly — keeping the password reset logic testable without a live SMTP server</li>
 *   <li>The implementation can be swapped (e.g., switch from Gmail SMTP to SendGrid)
 *       without touching any callers</li>
 * </ul>
 *
 * <p>The implementation ({@link EmailServiceImpl}) handles the case where Gmail
 * credentials are not configured: it logs a warning and returns without throwing,
 * so the rest of the application (registration, login, token refresh) continues to
 * work even when email is not set up.
 */
public interface EmailService {

    /**
     * Sends a password reset email containing a one-click reset link.
     *
     * <p>If mail is not configured (empty {@code MAIL_USERNAME} in the environment),
     * the implementation logs a warning and returns silently — the reset token is still
     * created in the database, but no email is sent.
     *
     * @param to        the recipient's email address
     * @param resetLink the full reset URL (e.g., {@code http://localhost:3000/reset-password?token=...})
     */
    void sendPasswordResetEmail(String to, String resetLink);
}
