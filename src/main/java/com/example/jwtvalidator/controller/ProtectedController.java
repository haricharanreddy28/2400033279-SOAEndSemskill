package com.example.jwtvalidator.controller;

import com.example.jwtvalidator.service.JwtTokenValidator;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Example protected resource that requires a valid JWT in the Authorization header.
 */
@RestController
@RequestMapping("/api/protected")
@RequiredArgsConstructor
@Tag(name = "Protected Resources", description = "Endpoints that require a valid JWT")
public class ProtectedController {

    private final JwtTokenValidator jwtTokenValidator;

    @GetMapping("/profile")
    @Operation(summary = "Get user profile (protected)",
               description = "Requires Bearer token in Authorization header",
               security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<?> getProfile(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

        // Check header presence
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body(Map.of(
                    "error", "Missing or invalid Authorization header",
                    "hint", "Send: Authorization: Bearer <your-token>"
            ));
        }

        String token = authHeader.substring(7); // strip "Bearer "

        // Validate
        Map<String, Object> validation = jwtTokenValidator.validateToken(token);

        if (!(boolean) validation.get("valid")) {
            return ResponseEntity.status(401).body(validation);
        }

        // Token is valid — return the protected resource
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = (Map<String, Object>) validation.get("claims");

        return ResponseEntity.ok(Map.of(
                "message", "Access granted to protected resource",
                "user", claims.get("subject"),
                "role", claims.get("role"),
                "allClaims", claims
        ));
    }

    @GetMapping("/admin")
    @Operation(summary = "Admin-only resource",
               description = "Requires Bearer token with role=ADMIN",
               security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<?> adminOnly(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body(Map.of(
                    "error", "Missing or invalid Authorization header"
            ));
        }

        String token = authHeader.substring(7);
        Map<String, Object> validation = jwtTokenValidator.validateToken(token);

        if (!(boolean) validation.get("valid")) {
            return ResponseEntity.status(401).body(validation);
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> claims = (Map<String, Object>) validation.get("claims");
        String role = (String) claims.get("role");

        if (!"ADMIN".equalsIgnoreCase(role)) {
            return ResponseEntity.status(403).body(Map.of(
                    "error", "Forbidden — ADMIN role required",
                    "yourRole", role
            ));
        }

        return ResponseEntity.ok(Map.of(
                "message", "Welcome, Admin!",
                "secretData", "This is admin-only content",
                "user", claims.get("subject")
        ));
    }
}
