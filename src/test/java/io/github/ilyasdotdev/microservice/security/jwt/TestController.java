package io.github.ilyasdotdev.microservice.security.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Muhammad Ilyas (m.ilyas@live.com)
 */
@RestController
@RequestMapping("/api/test")
@RequiredArgsConstructor
class TestController {

    private final AuthService authService;

    /**
     * Endpoint to test success response
     *
     * @return ResponseEntity with HTTP 200 OK status
     */
    @GetMapping
    public ResponseEntity<Void> testEndpoint() {
        return ResponseEntity.ok().build();
    }

    @GetMapping("/context")
    public Jwt getContext() {
        return authService.getAuthenticatedPrincipal();
    }

    @GetMapping("/forbidden")
    public ResponseEntity<Void> forbiddenEndpoint() {
        return ResponseEntity.ok().build(); // HTTP 403 Forbidden
    }

}
