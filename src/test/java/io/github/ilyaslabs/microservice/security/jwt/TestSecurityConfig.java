package io.github.ilyaslabs.microservice.security.jwt;

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
                                .requestMatchers("/api/test/unauthorized-scope").hasAuthority("SCOPE_USER")
                                .anyRequest().authenticated()
                );

        return http.build();

    }
}
