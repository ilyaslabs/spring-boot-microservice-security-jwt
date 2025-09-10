package io.github.ilyaslabs.microservice.security.jwt;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

/**
 * Configuration properties for JWT security settings.
 */
@ConfigurationProperties(prefix = "io.github.ilyaslabs.microservice.security.jwt")
@Data
public class JwtProperties {

    private ChronoUnit expiryUnit = ChronoUnit.MINUTES;
    private Long expiry = 60L; // Default to 60 minutes

    private ChronoUnit refreshExpiryUnit = ChronoUnit.DAYS;
    private Long refreshExpiry = 30L; // Default to 30 days

    /**
     * Calculates the expiration time in seconds based on the defined expiry value and unit.
     *
     * @return the expiration time in seconds as a Long.
     */
    public Long getExpiryInSeconds() {
        return Duration.of(expiry, expiryUnit).getSeconds();
    }
}
