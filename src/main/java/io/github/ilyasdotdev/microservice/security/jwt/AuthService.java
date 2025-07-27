package io.github.ilyasdotdev.microservice.security.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Service for handling JWT token generation and validation.
 * Also provide few helpful methods
 *
 * @author Muhammad Ilyas (m.ilyas@live.com)
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtEncoder encoder;
    private final JwtProperties jwtProperties;

    /**
     * Representing the scope claim key in the JWT token
     */
    public static final String KEY_SCOPE_CLAIM = "scope";

    /**
     * Generates a JWT token with the specified subject, issuer, claims, and scopes.
     *
     * @param subject the subject of the token
     * @param issuer  the issuer of the token
     * @param claims  additional claims to include in the token
     * @param scopes  the scopes associated with the token
     * @return the generated JWT token as a string
     */
    public String generateToken(
            String subject,
            String issuer,
            Map<String, String> claims,
            List<String> scopes) {
        return encoder
                .encode(JwtEncoderParameters.from(buildClaims(subject, issuer, claims, scopes)))
                .getTokenValue();
    }

    private JwtClaimsSet buildClaims(String subject,
                                     String issuer,
                                     Map<String, String> claims,
                                     List<String> scopes) {

        JwtClaimsSet.Builder claimSet = JwtClaimsSet.builder()
                .subject(subject)
                .issuer(issuer)
                .issuedAt(Instant.now())
                .expiresAt(getExpiresAt());

        if (scopes != null && !scopes.isEmpty()) {
            claimSet.claim(KEY_SCOPE_CLAIM, String.join(" ", scopes));
        }

        if (claims != null && !claims.isEmpty()) {
            claims.forEach(claimSet::claim);
        }

        return claimSet.build();
    }

    /**
     * Calculates the expiration time for the JWT token.
     *
     * @return the expiration instant
     */
    private Instant getExpiresAt() {
        return Instant.now().plusSeconds(jwtProperties.getExpiryInSeconds());
    }

    /**
     * Checks if the authenticated user has the specified scope.
     *
     * @param scope the scope to check for
     * @return true if the user has the specified scope, false otherwise
     */
    public boolean hasScope(String scope) {

        Jwt jwt = getAuthenticatedPrincipal();
        String currentScope = (String) jwt.getClaims().get(KEY_SCOPE_CLAIM);
        return Arrays.stream(currentScope.split(" ")).anyMatch(s -> s.equalsIgnoreCase(scope));
    }

    /**
     * Retrieves the authenticated principal from the security context.
     *
     * @return the authenticated Jwt principal
     */
    public Jwt getAuthenticatedPrincipal() {
        return (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
}
