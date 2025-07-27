package io.github.ilyasdotdev.microservice.security.jwt;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Configuration properties for RSA keys used in JWT signing.
 * @author Muhammad Ilyas (m.ilyas@live.com)
 */
@ConfigurationProperties(prefix = "io.github.ilyasdotdev.microservice.security.jwt.rsa")
@Data
public class RsaKeyProperties {
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;
}
