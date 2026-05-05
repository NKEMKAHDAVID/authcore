package com.authcore.security;

import com.authcore.exception.AuthException;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final TokenBlacklistService tokenBlacklistService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // 1. Extract the Authorization header
        String authHeader = request.getHeader("Authorization");

        // 2. If there's no Bearer token, pass the request along unauthenticated.
        //    Spring Security will then enforce access rules — public routes pass,
        //    protected routes get a 401.
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7); // strip "Bearer "

        try {
            // 3. Check blacklist BEFORE validating signature (fast Redis check first)
            if (tokenBlacklistService.isBlacklisted(token)) {
                log.debug("Rejected blacklisted token");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token has been revoked");
                return;
            }

            // 4. Validate signature + expiry, extract claims
            Claims claims = jwtService.validateAndExtractClaims(token);

            // 5. Only access tokens should be used for authentication
            //    Refresh tokens hitting protected endpoints get rejected here
            String tokenType = claims.get("type", String.class);
            if (!"access".equals(tokenType)) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token type");
                return;
            }

            // 6. Build the Spring Security authentication object
            Set<String> roles = jwtService.extractRoles(claims);
            List<SimpleGrantedAuthority> authorities = roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .toList();

            // The principal here is the userId string — controllers can extract it
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            jwtService.extractUserId(claims).toString(),  // principal = userId
                            null,                                          // credentials = null (token already validated)
                            authorities
                    );

            // Attach request details for audit logging downstream
            authentication.setDetails(request.getRemoteAddr());

            // 7. Set authentication in Spring Security context for this request
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (AuthException e) {
            log.debug("JWT validation failed: {}", e.getMessage());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
            return;
        }

        filterChain.doFilter(request, response);
    }
}