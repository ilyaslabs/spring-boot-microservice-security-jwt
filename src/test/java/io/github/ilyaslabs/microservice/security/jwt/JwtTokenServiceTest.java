package io.github.ilyaslabs.microservice.security.jwt;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.annotation.DirtiesContext;

import java.net.MalformedURLException;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Test class for {@link JwtTokenService}.
 *
 * @author ilyas
 */
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@Import(TestFixedClockConfiguration.class)
class JwtTokenServiceTest extends BaseTest {

    @Autowired
    private JwtProperties jwtProperties;

    @Autowired
    private TestFixedClockConfiguration.MutableClock clock;

    @Test
    void testGenerateToken() throws MalformedURLException {

        var scopes = List.of("ADMIN", "USER");

        Jwt jwt = jwtTokenService.generateToken(
                "testSubject",
                "http://www.testIssuer.com",
                Map.of("k1", "v1", "k2", "v2"),
                scopes
        );

        assertThat(jwt).isNotNull();
        assertThat(jwt.getTokenValue()).isNotBlank();
        assertThat(jwt.getSubject()).isEqualTo("testSubject");
        assertThat(jwt.getIssuer()).isEqualTo(URI.create("http://www.testIssuer.com").toURL());
        assertThat(jwt.getClaims()).containsEntry("k1", "v1");
        assertThat(jwt.getClaims()).containsEntry("k2", "v2");
        assertThat(jwt.getClaimAsString(JwtTokenService.KEY_SCOPE_CLAIM).split(" ")).contains(scopes.toArray(String[]::new));
    }

    @Test
    void testGetAuthenticatedPrincipal() throws Exception {

        Instant now = Instant.now();
        clock.set(now);

        Jwt jwt = generateTestToken();
        String responseString = mockMvc.perform(get("/api/test/context")
                        .header("Authorization", "Bearer " + jwt.getTokenValue()))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse().getContentAsString();

        assertThat(responseString).isNotBlank();

        assertThat(jwt.getSubject()).isEqualTo("testSubject");
        assertThat(jwt.getTokenValue()).isNotBlank();

        assertThat(jwt.getIssuer()).isEqualTo(URI.create("https://ilyaslabs.github.io").toURL());
        assertThat(jwt.getClaims()).containsEntry("k1", "v1");
        assertThat(jwt.getClaims()).containsEntry("k2", "v2");


        var expectedExpiryTime = now.plus(jwtProperties.getExpiry(), jwtProperties.getExpiryUnit());

        assertThat(jwt.getExpiresAt()).isEqualTo(expectedExpiryTime);
    }

    @Test
    void testGenerateRefreshToken() throws Exception {
        var now = Instant.now();
        clock.set(now);

        Jwt jwt = jwtTokenService.generateRefreshToken("test", "https://ilyaslabs.github.io", null, null);


        assertThat(jwt).isNotNull();
        assertThat(jwt.getSubject()).isEqualTo("test");
        assertThat(jwt.getTokenValue()).isNotBlank();
        assertThat(jwt.getIssuer()).isEqualTo(URI.create("https://ilyaslabs.github.io").toURL());
        assertThat(jwt.getClaims()).containsEntry(JwtTokenService.KEY_SCOPE_CLAIM, JwtTokenService.SCOPE_REFRESH_TOKEN);

        var expectedExpiryTime = now.plus(jwtProperties.getRefreshExpiry(), jwtProperties.getRefreshExpiryUnit());
        assertThat(jwt.getExpiresAt()).isEqualTo(expectedExpiryTime);
    }

    @Test
    void testGenerateRefreshTokenWithScopes() throws Exception {
        var now = Instant.now();
        clock.set(now);

        Jwt jwt = jwtTokenService.generateRefreshToken("test", "https://ilyaslabs.github.io", null, List.of("USER"));

        assertThat(jwt).isNotNull();
        assertThat(jwt.getSubject()).isEqualTo("test");
        assertThat(jwt.getTokenValue()).isNotBlank();
        assertThat(jwt.getIssuer()).isEqualTo(URI.create("https://ilyaslabs.github.io").toURL());
        assertThat(jwt.getClaimAsString(JwtTokenService.KEY_SCOPE_CLAIM).split(" ")).contains(List.of(JwtTokenService.SCOPE_REFRESH_TOKEN, "USER").toArray(String[]::new));

        var expectedExpiryTime = now.plus(jwtProperties.getRefreshExpiry(), jwtProperties.getRefreshExpiryUnit());
        assertThat(jwt.getExpiresAt()).isEqualTo(expectedExpiryTime);
    }

    @Test
    void testForbiddenEndpoint() throws Exception {
        var now = Instant.now();
        clock.set(now);

        Jwt jwt = generateTestToken();
        mockMvc.perform(get("/api/test/forbidden")
                        .header("Authorization", "Bearer " + jwt.getTokenValue()))
                .andExpect(status().isForbidden());
    }

    @Test
    void testUnauthenticatedEndpoint() throws Exception {
        mockMvc.perform(
                        get("/api/test/unauthorized-scope")
                )
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testForbiddenWhenNotAccess() throws Exception {

        mockMvc
                .perform(get("/api/test/unauthorized-scope")
                        .with(jwt()))
                .andExpect(status().isForbidden());
    }
}