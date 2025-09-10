package io.github.ilyaslabs.microservice.security.jwt;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;


/**
 * Security configuration for the application.
 */
@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final RsaKeyProperties rsaKeyProperties;

    /**
     * Creates basic filter chain required for microservice security.
     *
     * @param http the HttpSecurity object to configure
     * @return the configured HttpSecurity object
     * @throws Exception if an error occurs during configuration
     */
    @Bean
    @Primary
    public HttpSecurity httpSecurity(HttpSecurity http) throws Exception {

        http
                .csrf(AbstractHttpConfigurer::disable)
                //make session less
                .sessionManagement(customizer ->
                        customizer
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .cors(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .oauth2ResourceServer(oauth -> oauth.jwt(withDefaults()))
                .exceptionHandling(customizer ->
                        customizer
                                .authenticationEntryPoint(new HttpAccessDeniedEntryPoint())
                );

        return http;
    }

    @Bean(name = "defaultSecurityFilterChain")
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        log.info("Configuring default security filter chain");
        return http.build();
    }

    /**
     * Provides a PasswordEncoder bean for encoding passwords.
     *
     * @return a PasswordEncoder instance
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Creates a JwtDecoder bean for decoding JWT tokens.
     *
     * @return a JwtDecoder instance
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(rsaKeyProperties.getRsaPublicKey()).build();
    }

    /**
     * Creates a JwtEncoder bean for encoding JWT tokens.
     *
     * @return a JwtEncoder instance
     */
    @Bean
    public JwtEncoder jwtEncoder() {
        RSAKey rsaKey = new RSAKey.Builder(rsaKeyProperties.getRsaPublicKey()).privateKey(rsaKeyProperties.getRsaPrivateKey()).build();
        ImmutableJWKSet<SecurityContext> securityContextImmutableJWKSet = new ImmutableJWKSet<>(new JWKSet(rsaKey));
        return new NimbusJwtEncoder(securityContextImmutableJWKSet);
    }
}
