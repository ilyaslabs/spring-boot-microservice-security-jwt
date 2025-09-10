package io.github.ilyaslabs.microservice.security.jwt;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 *
 * @author Muhammad Ilyas (m.ilyas@live.com)
 */
@ComponentScan(basePackages = "io.github.ilyaslabs.microservice.security.jwt")
@Configuration
@EnableConfigurationProperties({
        RsaKeyProperties.class,
        JwtProperties.class
})
class AutoConfig {

    @Bean
    @ConditionalOnMissingBean(Clock.class)
    Clock clock() {
        return Clock.systemUTC();
    }
}
