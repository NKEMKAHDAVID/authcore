package com.authcore.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    // Redis key prefix — keeps blacklisted tokens in their own namespace
    private static final String BLACKLIST_PREFIX = "blacklist:";

    private final StringRedisTemplate redisTemplate;

    /**
     * Adds an access token to the Redis blacklist.
     *
     * Why TTL matches the token's remaining lifetime:
     * Once the token would have expired naturally, it is already invalid
     * and we no longer need to store it. This keeps Redis memory bounded.
     *
     * @param token          the raw JWT string
     * @param remainingMillis time until the token expires (System.currentTimeMillis() subtracted from token expiry)
     */
    public void blacklist(String token, long remainingMillis) {
        if (remainingMillis <= 0) {
            // Token is already expired — no point storing it
            return;
        }
        String key = BLACKLIST_PREFIX + token;
        redisTemplate.opsForValue().set(key, "revoked", remainingMillis, TimeUnit.MILLISECONDS);
        log.debug("Access token blacklisted, TTL: {}ms", remainingMillis);
    }

    /**
     * Returns true if this token has been explicitly revoked (i.e. the user logged out).
     * Called on every authenticated request by JwtAuthFilter.
     */
    public boolean isBlacklisted(String token) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(BLACKLIST_PREFIX + token));
    }
}