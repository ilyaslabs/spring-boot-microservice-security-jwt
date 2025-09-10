package io.github.ilyaslabs.microservice.security.jwt;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;

/**
 *
 * @author Muhammad Ilyas (m.ilyas@live.com)
 */
@TestConfiguration
public class TestFixedClockConfiguration {

    public static final String TIME = "2020-01-01T10:15:30.00Z";

    @Bean
    MutableClock clock() {
        return new MutableClock(Instant.parse(TIME), ZoneId.of("UTC"));
    }

    public static class MutableClock extends Clock {

        private Instant instant;
        private final ZoneId zone;

        public MutableClock(Instant fixedInstant, ZoneId zone) {
            this.instant = fixedInstant;
            this.zone = zone;
        }

        @Override
        public ZoneId getZone() {
            return zone;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return new MutableClock(instant, zone);
        }

        @Override
        public Instant instant() {
            return instant;
        }

        public void add(Duration duration) {
            this.instant = instant.plus(duration);
        }

        public void subtract(Duration duration) {
            this.instant = instant.minus(duration);
        }

        public void set(Instant newInstant) {
            this.instant = newInstant;
        }
    }

}
