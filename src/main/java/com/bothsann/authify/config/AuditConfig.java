package com.bothsann.authify.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/**
 * Enables Spring Data JPA Auditing for the entire application.
 *
 * <h2>Why is {@code @EnableJpaAuditing} here and NOT on {@code @SpringBootApplication}?</h2>
 *
 * <p>Spring Boot supports "test slicing" — you can load only a slice of the application
 * context for focused tests. The {@code @DataJpaTest} slice, for example, loads only
 * JPA-related beans (repositories, entities, datasource) and deliberately excludes
 * Spring Security beans, web beans, mail beans, etc.
 *
 * <p>If {@code @EnableJpaAuditing} were placed on the main {@code @SpringBootApplication}
 * class, then {@code @DataJpaTest} would try to process it — and fail, because the
 * auditing infrastructure can require beans (like a custom {@code AuditorAware}) that
 * are only available in a full context. Even without a custom {@code AuditorAware}, this
 * causes brittle test setups.
 *
 * <p>By isolating {@code @EnableJpaAuditing} in its own {@code @Configuration} class,
 * we gain:
 * <ul>
 *   <li>A full application context picks it up automatically (no change to behavior).</li>
 *   <li>A {@code @DataJpaTest} slice can exclude this config with
 *       {@code @ImportAutoConfiguration(exclude = AuditConfig.class)} if needed.</li>
 *   <li>Single Responsibility: the main class stays clean — it only bootstraps Spring Boot.</li>
 * </ul>
 *
 * <p>This is a widely recommended Spring Boot pattern. See Spring's own documentation
 * on "slice tests" for more context.
 */
@Configuration
@EnableJpaAuditing
public class AuditConfig {
    // No beans needed here — @EnableJpaAuditing registers all required
    // auditing infrastructure beans (AuditingEntityListener, etc.) automatically.
}
