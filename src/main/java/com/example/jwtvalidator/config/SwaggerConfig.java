package com.example.jwtvalidator.config;

import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@SecurityScheme(
        name = "bearerAuth",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT",
        description = "Paste your JWT token here (without 'Bearer ' prefix)"
)
public class SwaggerConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("JWT Validator API")
                        .version("1.0.0")
                        .description("""
                                **JWT Validation & Claims Extraction Service**

                                **Testing flow:**
                                1. `POST /api/auth/token` — generate a token
                                2. `POST /api/auth/validate` — validate it & see claims
                                3. Use the 🔒 Authorize button (top-right) to set the token
                                4. Hit the protected endpoints
                                """)
                        .contact(new Contact()
                                .name("BARG Info Solutions")
                                .url("https://barg.co.in")));
    }
}
