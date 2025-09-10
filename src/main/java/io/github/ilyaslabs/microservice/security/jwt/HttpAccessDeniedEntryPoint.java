package io.github.ilyaslabs.microservice.security.jwt;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

/**
 * Custom entry point for handling access denied exceptions in a Spring Security context.
 * This class implements the AuthenticationEntryPoint interface to provide a custom response
 * when an authenticated user tries to access a resource they are not authorized to access.
 *
 * @author Muhammad Ilyas
 */
public class HttpAccessDeniedEntryPoint implements AuthenticationEntryPoint {

    /**
     * {@inheritDoc}
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.getWriter().println("""
                {"message": "forbidden"}
                """);
    }
}
