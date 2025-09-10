package io.github.ilyaslabs.microservice.security.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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
    private final Clock clock;

    /**
     * Representing the scope claim key in the JWT token
     */
    public static final String KEY_SCOPE_CLAIM = "scope";

    /**
     * Representing the scope of refresh token
     */
    public static final String SCOPE_REFRESH_TOKEN = "REFRESH_TOKEN";

    /**
     * Generates a JWT token with the specified subject, issuer, claims, and scopes.
     *
     * @param subject the subject of the token
     * @param issuer  the issuer of the token
     * @param claims  additional claims to include in the token
     * @param scopes  the scopes associated with the token
     * @param expiry the expiry after now
     * @return the generated JWT token as a string
     */
    public String generateToken(
            String subject,
            String issuer,
            Map<String, String> claims,
            List<String> scopes,
            Duration expiry) {
        return encoder
                .encode(JwtEncoderParameters.from(buildClaims(subject, issuer, claims, scopes, expiry)))
                .getTokenValue();
    }

    /**
     * Generates a JWT token with the specified subject, issuer, claims, and scopes.
     * @param subject the subject of the token
     * @param issuer the issuer of the token
     * @param claims additional claims to include in the token
     * @param scopes the scopes associated with the token
     * @return the generated JWT token as a string
     */
    public String generateToken(
            String subject,
            String issuer,
            Map<String, String> claims,
            List<String> scopes) {
        return generateToken(subject, issuer, claims, scopes, Duration.of(jwtProperties.getExpiry(), jwtProperties.getExpiryUnit()));
    }

    /**
     * Generates a refresh JWT token with the specified subject, issuer, and claims.
     * @param subject the subject of the token
     * @param issuer the issuer of the token
     * @param claims additional claims to include in the token
     * @param scopes the scopes associated with the token, if null or empty, only REFRESH_TOKEN scope will be added
     * @return the generated refresh JWT token as a string
     */
    public String generateRefreshToken(
            String subject,
            String issuer,
            Map<String, String> claims,
            List<String> scopes) {
        scopes = Optional.
                ofNullable(scopes)
                .map(list -> {
                    var listWithRefreshScope = new ArrayList<>(list);
                    listWithRefreshScope.add(SCOPE_REFRESH_TOKEN);
                    return (List<String>)listWithRefreshScope;
                })
                .orElse(List.of(SCOPE_REFRESH_TOKEN));

        return generateToken(subject, issuer, claims, scopes, Duration.of(jwtProperties.getRefreshExpiry(), jwtProperties.getRefreshExpiryUnit()));
    }

    /**
     * Builds the JWT claims set with the specified parameters.
     *
     * @param subject the subject of the token
     * @param issuer  the issuer of the token
     * @param claims  additional claims to include in the token
     * @param scopes  the scopes associated with the token
     * @param expiry the expiry after now
     * @return the constructed JwtClaimsSet
     */
    private JwtClaimsSet buildClaims(String subject,
                                     String issuer,
                                     Map<String, String> claims,
                                     List<String> scopes,
                                     Duration expiry) {

        JwtClaimsSet.Builder claimSet = JwtClaimsSet.builder()
                .subject(subject)
                .issuer(issuer)
                .issuedAt(Instant.now(clock))
                .expiresAt(Instant.now(clock).plusSeconds(expiry.getSeconds()));

        if (scopes != null && !scopes.isEmpty()) {
            claimSet.claim(KEY_SCOPE_CLAIM, String.join(" ", scopes));
        }

        if (claims != null && !claims.isEmpty()) {
            claims.forEach(claimSet::claim);
        }

        return claimSet.build();
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
     * Retrieves a specific claim from the authenticated user's JWT token.
     *
     * @param claim the name of the claim to retrieve
     * @param clazz the expected type of the claim value
     * @param <T>   the type of the claim value
     * @return an Optional containing the claim value if present and of the correct type, otherwise an empty Optional
     */
    public <T> Optional<T> getClaim(String claim, Class<T> clazz) {
        Jwt jwt = getAuthenticatedPrincipal();
        return Optional.ofNullable(jwt.getClaims().get(claim))
                .filter(clazz::isInstance)
                .map(clazz::cast);
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
