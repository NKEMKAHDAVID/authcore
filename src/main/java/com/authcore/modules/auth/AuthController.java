package com.authcore.modules.auth;

import com.authcore.modules.auth.dto.*;
import com.authcore.shared.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<AuthResponse>> register(
            @Valid @RequestBody RegisterRequest request) {

        AuthResponse response = authService.register(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(ApiResponse.success("Registration successful", response));
    }
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request) {

        AuthResponse response = authService.login(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(ApiResponse.success("Login successful", response));
    }
    @PostMapping("/send-verification")
    public ResponseEntity<ApiResponse<Void>> send_verification(
            @Valid @RequestBody SendVerificationRequest request){
        authService.sendVerification(request);

        return ResponseEntity
                .status(HttpStatus.ACCEPTED)
                .body(ApiResponse.success("Verification code sent successfully"));
    }
    @PostMapping("/verify-email")
    public ResponseEntity<ApiResponse<Void>>verify_user(
            @Valid @RequestBody VerifyEmailRequest request){
        authService.verifyEmail(request);

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(ApiResponse.success("Verification successful"));
    }
}