package io.github.ilyasdotdev.microservice.security.jwt;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
*
* @author Muhammad Ilyas (m.ilyas@live.com)
*/
@Configuration
@EnableConfigurationProperties({
        RsaKeyProperties.class,
        JwtProperties.class
})
class Config {
}
