package com.example.jwtvalidator.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * STEP 1: Token Validator Function
 *
 * Responsibilities:
 *  - Decode JWT token
 *  - Verify signature against secret key
 *  - Check expiration
 *  - Extract embedded claims (subject, roles, custom claims)
 */
@Service
public class JwtTokenValidator {

    private final SecretKey signingKey;
    private final long expirationMs;

    public JwtTokenValidator(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration-ms}") long expirationMs) {
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expirationMs = expirationMs;
    }

    // ── Generate a token (for testing purposes) ──────────────────────────

    public String generateToken(String subject, String role, Map<String, Object> extraClaims) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);

        JwtBuilder builder = Jwts.builder()
                .subject(subject)
                .claim("role", role)
                .issuedAt(now)
                .expiration(expiry)
                .signWith(signingKey);

        if (extraClaims != null) {
            extraClaims.forEach(builder::claim);
        }

        return builder.compact();
    }

    // ── Validate and extract claims ──────────────────────────────────────

    /**
     * Core validation method.
     * Returns a result map with:
     *   valid    : boolean
     *   claims   : Map of all claims (if valid)
     *   error    : error message (if invalid)
     */
    public Map<String, Object> validateToken(String token) {
        Map<String, Object> result = new HashMap<>();

        try {
            // 1. Parse → verifies signature + checks expiration automatically
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            // 2. Extract all claims into a readable map
            Map<String, Object> claimsMap = new HashMap<>();
            claimsMap.put("subject", claims.getSubject());
            claimsMap.put("issuedAt", claims.getIssuedAt());
            claimsMap.put("expiration", claims.getExpiration());
            claimsMap.put("role", claims.get("role", String.class));

            // Include any extra custom claims
            claims.forEach((key, value) -> {
                if (!claimsMap.containsKey(key)) {
                    claimsMap.put(key, value);
                }
            });

            result.put("valid", true);
            result.put("claims", claimsMap);

        } catch (ExpiredJwtException e) {
            result.put("valid", false);
            result.put("error", "Token has expired");
            result.put("expiredAt", e.getClaims().getExpiration());

        } catch (SignatureException e) {
            result.put("valid", false);
            result.put("error", "Invalid token signature — possible tampering");

        } catch (MalformedJwtException e) {
            result.put("valid", false);
            result.put("error", "Malformed token: " + e.getMessage());

        } catch (UnsupportedJwtException e) {
            result.put("valid", false);
            result.put("error", "Unsupported JWT format");

        } catch (IllegalArgumentException e) {
            result.put("valid", false);
            result.put("error", "Token is null or empty");
        }

        return result;
    }

    // ── Quick boolean check (for filters) ────────────────────────────────

    public boolean isTokenValid(String token) {
        return (boolean) validateToken(token).get("valid");
    }

    // ── Extract subject only ─────────────────────────────────────────────

    public String extractSubject(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return claims.getSubject();
    }
}
