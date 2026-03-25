package com.bothsann.authify.common.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Generic API response wrapper used by all controllers.
 *
 * <p>Every successful response is wrapped in this structure so clients receive
 * a consistent envelope regardless of endpoint:
 * <pre>
 * {
 *   "status": 200,
 *   "message": "Login successful",
 *   "data": { "accessToken": "...", "refreshToken": "..." },
 *   "timestamp": "2024-03-20T10:30:00"
 * }
 * </pre>
 *
 * <p>For responses that have no payload (e.g., logout, forgot-password),
 * use {@code ApiResponse<Void>} — the {@code data} field will be null in JSON.
 *
 * <p>Use the static factory methods ({@link #success(Object, String)} and
 * {@link #success(String)}) rather than the builder directly — they automatically
 * populate {@code status} and {@code timestamp}.
 *
 * @param <T> the type of the response payload
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ApiResponse<T> {

    /** HTTP status code mirrored in the body for client convenience. */
    private int status;

    /** Human-readable success message. */
    private String message;

    /** The actual response payload. Null for void responses. */
    private T data;

    /** Server time when the response was generated. */
    private LocalDateTime timestamp;

    /**
     * Creates a 200 OK response with a payload.
     *
     * @param data    the response payload
     * @param message a human-readable success message
     * @param <T>     the payload type
     * @return a fully populated {@code ApiResponse}
     */

    public static <T> ApiResponse<T> success(T data, String message) {
        return ApiResponse.<T>builder()
                .status(200)
                .message(message)
                .data(data)
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Creates a 200 OK response with no payload (e.g., for logout or void operations).
     *
     * @param message a human-readable success message
     * @return an {@code ApiResponse<Void>} with null {@code data}
     */
    public static ApiResponse<Void> success(String message) {
        return ApiResponse.<Void>builder()
                .status(200)
                .message(message)
                .data(null)
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Creates a response with a specific HTTP status code and payload.
     * Used when the status code differs from 200 (e.g., 201 Created on register).
     *
     * @param status  the HTTP status code
     * @param data    the response payload
     * @param message a human-readable success message
     * @param <T>     the payload type
     * @return a fully populated {@code ApiResponse}
     */
    public static <T> ApiResponse<T> of(int status, T data, String message) {
        return ApiResponse.<T>builder()
                .status(status)
                .message(message)
                .data(data)
                .timestamp(LocalDateTime.now())
                .build();
    }
}
