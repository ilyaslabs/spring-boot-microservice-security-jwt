package io.github.ilyasdotdev.microservice.security.jwt;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

/**
 * Configuration properties for JWT security settings.
 */
@ConfigurationProperties(prefix = "io.github.ilyasdotdev.microservice.security.jwt")
@Data
public class JwtProperties {

    private ChronoUnit expiryUnit = ChronoUnit.MINUTES;
    private Integer expiry = 60; // Default to 60 minutes

    /**
     * Calculates the expiration time in seconds based on the defined expiry value and unit.
     *
     * @return the expiration time in seconds as a Long.
     */
    public Long getExpiryInSeconds() {
        return Duration.of(expiry, expiryUnit).getSeconds();
    }
}
