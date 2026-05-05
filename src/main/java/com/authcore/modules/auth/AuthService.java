package com.authcore.modules.auth;

import com.authcore.exception.AuthException;
import com.authcore.modules.auth.dto.*;
import com.authcore.modules.token.EmailVerificationToken;
import com.authcore.modules.token.EmailVerificationTokenRepository;
import com.authcore.modules.token.RefreshToken;
import com.authcore.modules.token.RefreshTokenRepository;
import com.authcore.modules.user.AuthProvider;
import com.authcore.modules.user.Role;
import com.authcore.modules.user.RoleRepository;
import com.authcore.modules.user.User;
import com.authcore.modules.user.UserRepository;
import com.authcore.modules.user.UserStateService;
import com.authcore.security.JwtService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserStateService userStateService;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;

    // Refresh token expiry in milliseconds — used to set cookie max-age
    @Value("${jwt.refresh-expiration}")
    private long refreshExpirationMs;

    // ─────────────────────────────────────────────
    // REGISTER — unchanged from your original
    // ─────────────────────────────────────────────

    @Transactional
    public AuthResponse register(RegisterRequest request) {

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new AuthException(
                    "An account with this email already exists",
                    HttpStatus.CONFLICT
            );
        }

        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new AuthException(
                        "Default role not found. Please contact support.",
                        HttpStatus.INTERNAL_SERVER_ERROR
                ));

        User user = User.builder()
                .firstName(request.getFirstName())
                .middleName(request.getMiddleName())
                .lastName(request.getLastName())
                .email(request.getEmail().toLowerCase().trim())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .provider(AuthProvider.LOCAL)
                .isVerified(false)
                .roles(Set.of(userRole))
                .build();

        User savedUser = userRepository.save(user);

        log.info("New user registered: {}", savedUser.getEmail());

        return AuthResponse.builder()
                .userId(savedUser.getId())
                .email(savedUser.getEmail())
                .firstName(savedUser.getFirstName())
                .lastName(savedUser.getLastName())
                .roles(savedUser.getRoles().stream()
                        .map(Role::getName)
                        .collect(Collectors.toSet()))
                .message("Registration successful. Please check your email to verify your account.")
                .build();
        // accessToken intentionally null — user must verify email before they can log in
    }

    // ─────────────────────────────────────────────
    // LOGIN — now issues JWT + sets refresh cookie
    // ─────────────────────────────────────────────

    @Transactional
    public AuthResponse login(LoginRequest request, HttpServletResponse httpResponse) {

        // 1. Find the user
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new AuthException("Incorrect email or password", HttpStatus.UNAUTHORIZED));

        // 2. Check lockout
        if (user.isLocked()) {
            if (user.getLockedUntil() != null && !LocalDateTime.now().isBefore(user.getLockedUntil())) {
                // Lock has expired — unlock the account
                user.setLocked(false);
                user.setLockedUntil(null);
                user.setFailedLoginAttempts(0);
                userStateService.saveUserState(user);
            } else {
                throw new AuthException("Account locked. Try again in 15 minutes.", HttpStatus.FORBIDDEN);
            }
        }

        // 3. Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            int attempts = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(attempts);

            if (attempts >= 5) {
                user.setLocked(true);
                user.setLockedUntil(LocalDateTime.now().plusMinutes(15));
            }

            userStateService.saveUserState(user);
            throw new AuthException("Incorrect email or password", HttpStatus.UNAUTHORIZED);
        }

        // 4. Require email verification
        if (!user.isVerified()) {
            throw new AuthException(
                    "Please verify your email address before logging in.",
                    HttpStatus.FORBIDDEN
            );
        }

        // 5. Reset failed attempts on successful login
        user.setFailedLoginAttempts(0);
        userRepository.save(user);

        // 6. Build roles set for the token
        Set<String> roles = user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet());

        // 7. Generate access token (short-lived, goes in response body)
        String accessToken = jwtService.generateAccessToken(user.getId(), user.getEmail(), roles);

        // 8. Generate refresh token (long-lived, goes in HttpOnly cookie)
        String rawRefreshToken = jwtService.generateRefreshToken(user.getId());

        // 9. Revoke any existing refresh tokens for this user before issuing a new one
        //    One active refresh token per user keeps things clean and detectable
        refreshTokenRepository.deleteByUser(user);

        // 10. Hash the refresh token before storing (never store raw tokens)
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .tokenHash(passwordEncoder.encode(rawRefreshToken))
                .expiresAt(LocalDateTime.now().plusSeconds(refreshExpirationMs / 1000))
                .build();
        refreshTokenRepository.save(refreshToken);

        // 11. Set refresh token as HttpOnly cookie
        //     HttpOnly = JavaScript cannot read it (XSS protection)
        //     Secure = only sent over HTTPS
        //     SameSite=Strict = not sent on cross-site requests (CSRF protection)
        Cookie refreshCookie = new Cookie("refresh_token", rawRefreshToken);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(true);   // set to false only in local dev if not using HTTPS
        refreshCookie.setPath("/api/v1/auth/refresh");  // only sent to the refresh endpoint
        refreshCookie.setMaxAge((int) (refreshExpirationMs / 1000));
        httpResponse.addCookie(refreshCookie);

        log.info("User logged in: {}", user.getEmail());

        return AuthResponse.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .roles(roles)
                .accessToken(accessToken)
                .message("Login successful.")
                .build();
    }

    // ─────────────────────────────────────────────
    // SEND VERIFICATION — unchanged
    // ─────────────────────────────────────────────

    @Transactional
    public void sendVerification(SendVerificationRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new AuthException("User not found", HttpStatus.NOT_FOUND));

        if (user.isVerified()) throw new AuthException("User is already verified", HttpStatus.CONFLICT);

        emailVerificationTokenRepository.deleteByUser(user);

        int intCode = ThreadLocalRandom.current().nextInt(100000, 1000000);
        String stringCode = String.valueOf(intCode);
        String hashedCode = passwordEncoder.encode(stringCode);

        EmailVerificationToken emailVerificationToken = EmailVerificationToken.builder()
                .user(user)
                .tokenHash(hashedCode)
                .used(false)
                .expiresAt(LocalDateTime.now().plusMinutes(30))
                .build();

        emailVerificationTokenRepository.save(emailVerificationToken);

        log.info("Verification code for {}: {}", user.getEmail(), intCode);
    }

    // ─────────────────────────────────────────────
    // VERIFY EMAIL — unchanged
    // ─────────────────────────────────────────────

    @Transactional
    public void verifyEmail(VerifyEmailRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new AuthException("User not found", HttpStatus.NOT_FOUND));

        if (user.isVerified()) throw new AuthException("User is already verified", HttpStatus.CONFLICT);

        EmailVerificationToken token = emailVerificationTokenRepository.findByUserAndUsedFalse(user)
                .orElseThrow(() -> new AuthException("No pending verification found", HttpStatus.NOT_FOUND));

        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new AuthException("This code has expired", HttpStatus.FORBIDDEN);
        }

        if (!passwordEncoder.matches(request.getVerificationCode(), token.getTokenHash())) {
            throw new AuthException("Invalid verification code", HttpStatus.FORBIDDEN);
        }

        token.setUsed(true);
        user.setVerified(true);
        userRepository.save(user);
        emailVerificationTokenRepository.save(token);
    }
}