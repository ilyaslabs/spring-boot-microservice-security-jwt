
# Getting Started

A library to quickly set up JWT authentication in a Spring Boot application.
This library provides a simple way to generate and validate JWT tokens using RSA keys.

## Features
- Generate JWT tokens with RSA keys
- Validate JWT tokens
- Restrict access to endpoints based on scopes
- Customizable JWT claims
- Basic authentication

## How to use

1. Create a spring boot application using [start.spring.io](https://start.spring.io/)
2. Add the dependency in your project.
    ```xml
    <dependency>
        <groupId>io.github.ilyasdotdev</groupId>
        <artifactId>spring-boot-microservice-security-jwt</artifactId>
        <version>1.0.0</version>
    </dependency>
    ```

3. Execute below scripts in `src/main/resources` directory to create public and private keys.
    ```
    openssl genrsa -out keypair.pem 2048
    openssl rsa -in keypair.pem -pubout -out publickey.pem
    openssl rsa -in keypair.pem -out privatekey.pem
    ```
4. Add the keys to your `application.yml` file.
    ```yml
   io:
      github:
        ilyasdotdev:
          microservice:
            security:
              jwt:
                rsa:
                  private-key: classpath:privateKey.pem
                  public-key: classpath:publicKey.pem
    ```
   
   - Keys can be generated anywhere.

> That's all you need to do to get started with JWT authentication in your Spring Boot application.

# Detailed Documentation

## Generating JWT Token

While creating a web application there could be an end point which authenticate user and provide jwt token.

An `AuthService` bean is provided to generate JWT tokens. You can inject it in your controller class and can use to generate jwt token.

```java
String token = authService.generateToken(
                "user", // subject
                "https://www.domain.com", // issuer
                Map.of("k1", v1), // custom claims
                List.of("ADMIN") // scopes
        );
```

While consuming secured API's this token should be passed in the `Authorization` header as a Bearer token.
Then application will automatically validate the token for you.

## Changing JWT Token Expiry

By default, the token will be valid for 1 hour. You can change this by setting below property in your `application.yml` file.

```yml
io:
  github:
    ilyasdotdev:
      microservice:
        security:
          jwt:
            expiryUnit: HOURS # or MINUTES, DAYS, WEEKS // Any java.time.temporal.ChronoUnit
            expiry: 60 # value of the expiry unit
```
## Retrieving JWT
If you want to retrieve the JWT token from the request, you can use the `AuthService` bean.

```java
authService.getAuthenticatedPrincipal();
```
This will return the `org.springframework.security.oauth2.jwt.Jwt` object which contains the token and its claims.

## Restricting endpoint for specific scope

By default, A SecurityFilter chain is configured for you which can be overridden by creating your own `SecurityFilterChain` bean.

```java
@Bean
    public SecurityFilterChain SecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(customizer ->
                        customizer
                                .requestMatchers("/api/auth").permitAll()
                                .requestMatchers("/api/data").hasAuthority("SCOPE_ADMIN")
                                .requestMatchers("/api/**").authenticated()
                                .anyRequest().permitAll()
                );
        return http.build();
    }

```
Notice while generation token the scope was passed without `SCOPE_` prefix, But when using in filter chain it should be prefixed by `SCOPE_`

The `HttpSecurity` which is injected in security filter chain bean is already configured to.

1. Use JWT authentication.
2. Disable CSRF.
3. Disable form login.
4. Disable httpBasic.
5. Exception handling is configured to return 401 Unauthorized for unauthorized requests.

So, You don't have to do these configurations again.

> This library is also uses `spring-boot-microservice` dependency So you don't have to add it again in your project.

- Have a look at [spring-boot-microservice](https://github.com/ilyasdotdev/spring-boot-microservice) documentation.