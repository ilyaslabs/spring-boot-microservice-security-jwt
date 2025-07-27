package io.github.ilyasdotdev.microservice.security.jwt;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

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
class AuthServiceTest extends BaseTest {

    @Autowired
    private JwtProperties jwtProperties;

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
        assertThat(claims).containsEntry("iss", "https://ilyasdotdev.github.io");
        assertThat(claims).containsEntry("k1", "v1");
        assertThat(claims).containsEntry("k2", "v2");


        // formatter for LocalDateTime from format 2025-07-27T15:38:27Z
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'");
        var expiresAt = LocalDateTime.parse(map.get("expiresAt").toString(), formatter);
        var expectedExpiryTime = LocalDateTime.now(ZoneOffset.UTC).plus(jwtProperties.getExpiry(), jwtProperties.getExpiryUnit());

        assertThat(expiresAt).isBefore(expectedExpiryTime);
        assertThat(expiresAt).isAfter(expectedExpiryTime.minusSeconds(1));
    }

    @Test
    void testForbiddenEndpoint() throws Exception {
        String token = generateTestToken();
        mockMvc.perform(get("/api/test/forbidden")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }
}