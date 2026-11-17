package com.example.jwtvalidator.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ValidateRequest {

    @Schema(description = "JWT token string to validate",
            example = "eyJhbGciOiJIUzI1NiJ9...")
    @NotBlank(message = "Token is required")
    private String token;
}
