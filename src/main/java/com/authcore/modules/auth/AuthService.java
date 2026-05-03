package com.authcore.modules.auth;

import com.authcore.exception.AuthException;
import com.authcore.modules.auth.dto.AuthResponse;
import com.authcore.modules.auth.dto.LoginRequest;
import com.authcore.modules.auth.dto.RegisterRequest;
import com.authcore.modules.user.AuthProvider;
import com.authcore.modules.user.Role;
import com.authcore.modules.user.RoleRepository;
import com.authcore.modules.user.User;
import com.authcore.modules.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public AuthResponse register(RegisterRequest request) {

        // Step 1 — check email is not already taken
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new AuthException(
                    "An account with this email already exists",
                    HttpStatus.CONFLICT
            );
        }

        // Step 2 — fetch the default USER role
        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new AuthException(
                        "Default role not found. Please contact support.",
                        HttpStatus.INTERNAL_SERVER_ERROR
                ));

        // Step 3 — build the user object
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

        // Step 4 — save to database
        User savedUser = userRepository.save(user);

        log.info("New user registered: {}", savedUser.getEmail());

        // Step 5 — build and return response
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
    }

    public AuthResponse login(LoginRequest request){
        User user = userRepository.findByEmail(request.getEmail()).
                orElseThrow(() -> new AuthException("Incorrect User or Password",
                        HttpStatus.UNAUTHORIZED));

        if(!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())){
            throw new AuthException(
                    "Incorrect User or Password",
                    HttpStatus.UNAUTHORIZED);
        }
        if(!user.isVerified()){
            throw new AuthException(
                    "Go and verify your email",
                    HttpStatus.FORBIDDEN);
        }
        if(user.isLocked()){
            throw new AuthException(
                    "Wait and try again in 10 minutes",
                    HttpStatus.FORBIDDEN);
        }

        return AuthResponse.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .roles(user.getRoles().stream()
                        .map(Role::getName)
                        .collect(Collectors.toSet()))
                .message("Login successful.")
                .build();
    }
}