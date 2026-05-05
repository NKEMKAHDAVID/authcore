package com.authcore.modules.auth.dto;

import lombok.Builder;
import lombok.Getter;

import java.util.Set;
import java.util.UUID;

@Getter
@Builder
public class AuthResponse {

    private UUID userId;
    private String email;
    private String firstName;
    private String lastName;
    private Set<String> roles;
    private String message;

    // The short-lived JWT the client stores in memory (NOT localStorage)
    // Included on login. Null on register (user must verify email first).
    private String accessToken;
}