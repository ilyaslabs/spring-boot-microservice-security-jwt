package io.github.ilyaslabs.microservice.security.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

/**
 * @author Muhammad Ilyas (m.ilyas@live.com)
 */
@SpringBootTest
@AutoConfigureMockMvc
public abstract class BaseTest {

    @Autowired
    public MockMvc mockMvc;

    @Autowired
    public AuthService authService;

    /**
     * Generates a test token with predefined values.
     *
     * @return the generated JWT token as a String
     */
    public String generateTestToken() {

        return authService.generateToken(
                "testSubject",
                "https://ilyaslabs.github.io",
                Map.of("k1", "v1", "k2", "v2"),
                List.of("ADMIN", "USER")
        );
    }
}
