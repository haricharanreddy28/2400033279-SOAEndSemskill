package com.example.jwtvalidator.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.util.Map;

@Data
public class TokenRequest {

    @Schema(description = "Username / subject for the token", example = "gourav")
    @NotBlank(message = "Subject is required")
    private String subject;

    @Schema(description = "Role to embed in the token", example = "ADMIN")
    @NotBlank(message = "Role is required")
    private String role;

    @Schema(description = "Optional extra claims", example = "{\"department\": \"engineering\"}")
    private Map<String, Object> extraClaims;
}
