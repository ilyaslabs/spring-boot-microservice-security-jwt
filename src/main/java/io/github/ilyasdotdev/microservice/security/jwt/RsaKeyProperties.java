package io.github.ilyasdotdev.microservice.security.jwt;

import jakarta.annotation.PostConstruct;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Configuration properties for RSA keys used in JWT signing.
 *
 * @author Muhammad Ilyas (m.ilyas@live.com)
 */
@ConfigurationProperties(prefix = "io.github.ilyasdotdev.microservice.security.jwt.rsa")
@Data
public class RsaKeyProperties {

    private String publicKey;
    private String privateKey;

    private RSAPrivateKey rsaPrivateKey;
    private RSAPublicKey rsaPublicKey;

    @PostConstruct
    public void initKeys() throws Exception {
        if (rsaPrivateKey == null && privateKey != null) {
            rsaPrivateKey = loadPrivateKey(privateKey);
        }

        if (rsaPublicKey == null && publicKey != null) {
            rsaPublicKey = loadPublicKey(publicKey);
        }
    }

    private RSAPrivateKey loadPrivateKey(String key) throws Exception {
        String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) kf.generatePrivate(keySpec);
    }

    private RSAPublicKey loadPublicKey(String key) throws Exception {
        String publicKeyPEM = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(keySpec);
    }
}
