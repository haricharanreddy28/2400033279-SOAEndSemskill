package com.example.jwtvalidator.controller;

import com.example.jwtvalidator.dto.TokenRequest;
import com.example.jwtvalidator.dto.ValidateRequest;
import com.example.jwtvalidator.service.JwtTokenValidator;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * STEP 2: Validation Endpoints
 *
 * POST /api/auth/token      → generate a token (for testing)
 * POST /api/auth/validate   → validate a token & extract claims
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "JWT Auth", description = "Generate and validate JWT tokens")
public class AuthController {

    private final JwtTokenValidator jwtTokenValidator;

    // ── Generate Token ───────────────────────────────────────────────────

    @PostMapping("/token")
    @Operation(summary = "Generate JWT token",
               description = "Creates a signed JWT with subject, role, and optional extra claims")
    public ResponseEntity<Map<String, Object>> generateToken(
            @Valid @RequestBody TokenRequest request) {

        String token = jwtTokenValidator.generateToken(
                request.getSubject(),
                request.getRole(),
                request.getExtraClaims()
        );

        return ResponseEntity.ok(Map.of(
                "token", token,
                "type", "Bearer",
                "message", "Token generated — use POST /api/auth/validate to verify it"
        ));
    }

    // ── Validate Token ───────────────────────────────────────────────────

    @PostMapping("/validate")
    @Operation(summary = "Validate JWT token & extract claims",
               description = "Decodes the token, verifies signature, checks expiry, returns all claims")
    public ResponseEntity<Map<String, Object>> validateToken(
            @Valid @RequestBody ValidateRequest request) {

        Map<String, Object> result = jwtTokenValidator.validateToken(request.getToken());

        boolean valid = (boolean) result.get("valid");
        return valid
                ? ResponseEntity.ok(result)
                : ResponseEntity.status(401).body(result);
    }
}
