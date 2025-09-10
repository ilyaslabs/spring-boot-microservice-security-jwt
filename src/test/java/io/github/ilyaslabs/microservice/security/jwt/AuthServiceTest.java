package io.github.ilyaslabs.microservice.security.jwt;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Test class for {@link AuthService}.
 *
 * @author ilyas
 */
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@Import(TestFixedClockConfiguration.class)
class AuthServiceTest extends BaseTest {

    @Autowired
    private JwtProperties jwtProperties;

    @Autowired
    private TestFixedClockConfiguration.MutableClock clock;

    @Test
    void testGenerateToken() {

        String token = authService.generateToken(
                "testSubject",
                "testIssuer",
                Map.of("k1", "v1", "k2", "v2"),
                List.of("ADMIN", "USER")
        );

        assertThat(token).isNotBlank();
    }

    @Test
    void testGetAuthenticatedPrincipal() throws Exception {

        Instant now = Instant.now();
        clock.set(now);

        String token = generateTestToken();
        String responseString = mockMvc.perform(get("/api/test/context")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse().getContentAsString();

        assertThat(responseString).isNotBlank();

        Map<String, Object> map = new ObjectMapper().readValue(responseString, new TypeReference<Map<String, Object>>() {
        });

        Map<String, String> claims = (Map<String, String>) map.get("claims");

        assertThat(claims).containsEntry("sub", "testSubject");
        assertThat(map).containsEntry("tokenValue", token);
        assertThat(claims).containsEntry("iss", "https://ilyaslabs.github.io");
        assertThat(claims).containsEntry("k1", "v1");
        assertThat(claims).containsEntry("k2", "v2");

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'");
        var expiresAt = LocalDateTime.parse(map.get("expiresAt").toString(), formatter);
        var expectedExpiryTime = now.plus(jwtProperties.getExpiry(), jwtProperties.getExpiryUnit()).atZone(ZoneOffset.UTC).toLocalDateTime().withNano(0);

        assertThat(expiresAt.isEqual(expectedExpiryTime)).isTrue();
    }
    
    @Test
    void testGenerateRefreshToken() throws Exception {
        var now = Instant.now();
        clock.set(now);

        String token = authService.generateRefreshToken("test", "https://ilyaslabs.github.io", null, null);

        String responseString = mockMvc.perform(get("/api/test/context")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse().getContentAsString();

        assertThat(responseString).isNotBlank();

        Map<String, Object> map = new ObjectMapper().readValue(responseString, new TypeReference<Map<String, Object>>() {
        });

        Map<String, String> claims = (Map<String, String>) map.get("claims");

        String scope = claims.get(AuthService.KEY_SCOPE_CLAIM);

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'");
        var expiresAt = LocalDateTime.parse(map.get("expiresAt").toString(), formatter);
        var expectedExpiryTime = now.plus(jwtProperties.getRefreshExpiry(), jwtProperties.getRefreshExpiryUnit()).atZone(ZoneOffset.UTC).toLocalDateTime().withNano(0);

        assertThat(scope).isEqualTo(AuthService.SCOPE_REFRESH_TOKEN);
        assertThat(expiresAt.isEqual(expectedExpiryTime)).isTrue();
    }

    @Test
    void testGenerateRefreshTokenWithScopes() throws Exception {
        var now = Instant.now();
        clock.set(now);

        String token = authService.generateRefreshToken("test", "https://ilyaslabs.github.io", null, List.of("USER"));

        String responseString = mockMvc.perform(get("/api/test/context")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse().getContentAsString();

        assertThat(responseString).isNotBlank();

        Map<String, Object> map = new ObjectMapper().readValue(responseString, new TypeReference<Map<String, Object>>() {
        });

        Map<String, String> claims = (Map<String, String>) map.get("claims");
        String scope = claims.get(AuthService.KEY_SCOPE_CLAIM);

        assertThat(scope).contains(AuthService.SCOPE_REFRESH_TOKEN, "USER");
    }

    @Test
    void testForbiddenEndpoint() throws Exception {
        var now = Instant.now();
        clock.set(now);

        String token = generateTestToken();
        mockMvc.perform(get("/api/test/forbidden")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }
}