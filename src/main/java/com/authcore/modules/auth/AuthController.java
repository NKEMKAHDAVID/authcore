package com.authcore.modules.auth;

import com.authcore.modules.auth.dto.AuthResponse;
import com.authcore.modules.auth.dto.LoginRequest;
import com.authcore.modules.auth.dto.RegisterRequest;
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
}