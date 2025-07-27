package io.github.ilyasdotdev.microservice.security.jwt;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author Muhammad Ilyas (m.ilyas@live.com)
 */
@Configuration
class TestSecurityConfig {

    @Bean
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(customizer ->
                        customizer.requestMatchers("/api/test/forbidden").denyAll()
                                .anyRequest().authenticated()
                );

        return http.build();

    }
}
