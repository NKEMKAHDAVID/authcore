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
}