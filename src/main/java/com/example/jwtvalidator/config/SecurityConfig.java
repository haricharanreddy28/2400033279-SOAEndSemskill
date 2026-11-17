package com.example.jwtvalidator.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF (stateless API)
            .csrf(csrf -> csrf.disable())

            // Stateless sessions
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // Permit all — our controllers handle JWT validation manually
            // (In production, you'd add a JwtAuthenticationFilter here)
            .authorizeHttpRequests(auth -> auth
                    .anyRequest().permitAll()
            );

        return http.build();
    }
}
