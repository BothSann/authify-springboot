package com.bothsann.authify.common.audit;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.Getter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

/**
 * Abstract base class that provides automatic timestamp auditing for all entities.
 *
 * <p>By annotating this class with {@code @MappedSuperclass}, JPA will include these
 * fields in every entity that extends it — without creating a separate table for
 * {@code Auditable} itself. Think of it as a mixin: the columns are "injected" into
 * the child entity's table at the database level.
 *
 * <p>{@code @EntityListeners(AuditingEntityListener.class)} registers a JPA lifecycle
 * listener that Spring Data uses to intercept {@code @PrePersist} and {@code @PreUpdate}
 * events, automatically populating {@code createdAt} and {@code updatedAt} without any
 * manual code in the entity.
 *
 * <p>All entities in this project ({@code User}, {@code RefreshToken},
 * {@code PasswordResetToken}) extend this class to gain free timestamp tracking.
 */
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
@Getter
public abstract class Auditable {

    /**
     * Timestamp set once when the entity is first persisted.
     *
     * <p>{@code updatable = false} tells Hibernate to never include this column in
     * UPDATE statements — it is written once on INSERT and then locked. Without this,
     * a stray {@code save()} call could silently overwrite the original creation time.
     */
    @CreatedDate
    @Column(updatable = false)
    private LocalDateTime createdAt;

    /**
     * Timestamp updated automatically every time the entity is saved.
     *
     * <p>Spring Data's {@code AuditingEntityListener} sets this field on both
     * {@code @PrePersist} (first save) and {@code @PreUpdate} (subsequent saves).
     */
    @LastModifiedDate
    private LocalDateTime updatedAt;
}
