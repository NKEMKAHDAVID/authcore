package com.authcore.security;

import com.authcore.exception.AuthException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
public class JwtService {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final long accessTokenExpiration;   // milliseconds
    private final long refreshTokenExpiration;  // milliseconds

    // Spring reads these from application.properties which reads from your .env
    // JWT_PRIVATE_KEY and JWT_PUBLIC_KEY are base64-encoded PEM strings
    public JwtService(
            @Value("${jwt.private-key}") String privateKeyBase64,
            @Value("${jwt.public-key}") String publicKeyBase64,
            @Value("${jwt.expiration}") long accessTokenExpiration,
            @Value("${jwt.refresh-expiration}") long refreshTokenExpiration
    ) {
        this.accessTokenExpiration = accessTokenExpiration;
        this.refreshTokenExpiration = refreshTokenExpiration;
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");

            // Decode private key
            byte[] privateBytes = Base64.getDecoder().decode(stripPemHeaders(privateKeyBase64));
            this.privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));

            // Decode public key
            byte[] publicBytes = Base64.getDecoder().decode(stripPemHeaders(publicKeyBase64));
            this.publicKey = kf.generatePublic(new X509EncodedKeySpec(publicBytes));

        } catch (Exception e) {
            throw new IllegalStateException("Failed to load RSA keys. Check JWT_PRIVATE_KEY and JWT_PUBLIC_KEY in your .env", e);
        }
    }

    // ─────────────────────────────────────────────
    // TOKEN GENERATION
    // ─────────────────────────────────────────────

    /**
     * Generates a short-lived access token (default 15 minutes).
     * Contains userId, email, and roles as claims.
     * Signed with RS256 private key.
     */
    public String generateAccessToken(UUID userId, String email, Set<String> roles) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + accessTokenExpiration);

        return Jwts.builder()
                .subject(userId.toString())
                .claim("email", email)
                .claim("roles", roles)
                .claim("type", "access")
                .issuedAt(now)
                .expiration(expiry)
                .signWith(privateKey)   // jjwt 0.12.x infers RS256 from the key type
                .compact();
    }

    /**
     * Generates a long-lived refresh token (default 7 days).
     * Contains only userId — minimal claims by design.
     * This token's hash is stored in the database; it is NOT stored in Redis.
     */
    public String generateRefreshToken() {
        // Generates a cryptographically secure random 32-byte string
        // Short enough to BCrypt, impossible to guess
        byte[] randomBytes = new byte[32];
        new java.security.SecureRandom().nextBytes(randomBytes);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    // ─────────────────────────────────────────────
    // TOKEN VALIDATION
    // ─────────────────────────────────────────────

    /**
     * Validates a token and returns its claims.
     * Throws AuthException if expired, malformed, or signature is invalid.
     */
    public Claims validateAndExtractClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new AuthException("Token has expired", HttpStatus.UNAUTHORIZED);
        } catch (JwtException e) {
            throw new AuthException("Invalid token", HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * Extracts userId from a validated token without throwing on expiry.
     * Used during refresh — we need the userId even from an expired access token.
     * NOTE: Only use this when you have already validated the refresh token separately.
     */
    public UUID extractUserId(Claims claims) {
        return UUID.fromString(claims.getSubject());
    }

    public String extractEmail(Claims claims) {
        return claims.get("email", String.class);
    }

    @SuppressWarnings("unchecked")
    public Set<String> extractRoles(Claims claims) {
        return Set.copyOf(claims.get("roles", java.util.List.class));
    }

    /**
     * Returns the expiration time in milliseconds from epoch.
     * Used by TokenBlacklistService to set correct Redis TTL on logout.
     */
    public long getExpirationMillis(Claims claims) {
        return claims.getExpiration().getTime();
    }

    // ─────────────────────────────────────────────
    // HELPERS
    // ─────────────────────────────────────────────

    /**
     * Strips "-----BEGIN ...-----" PEM headers/footers and whitespace
     * so Base64.getDecoder() can parse the raw key bytes.
     */
    private String stripPemHeaders(String pem) {
        return pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
    }
}