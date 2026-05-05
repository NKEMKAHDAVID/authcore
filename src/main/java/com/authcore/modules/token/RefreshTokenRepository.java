package com.authcore.modules.token;

import com.authcore.modules.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    // Used during token rotation — find all active tokens for a user
    Optional<RefreshToken> findByUserAndRevokedFalse(User user);

    // Revoke all refresh tokens for a user (used on password reset / logout-all)
    @Modifying
    void deleteByUser(User user);
}