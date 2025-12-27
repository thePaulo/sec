package mycompany.ltda.sec.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class RedisRateLimiter {

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    private static final String RATE_LIMIT_KEY = "rate_limit";

    public boolean tryAcquire(String userId) {
        String key = RATE_LIMIT_KEY + ":" + userId;
        long currentTime = System.currentTimeMillis() / 1000; // current time in seconds
        String currentTimeStr = String.valueOf(currentTime);

        // Increment the request count for the user
        Long requestCount = redisTemplate.opsForValue().increment(key, 1);
        if (requestCount == 1) {
            redisTemplate.expire(key, Duration.ofSeconds(60)); // Expire after 1 minute
        }

        // If request count exceeds 100 within 60 seconds, rate limit exceeded
        if (requestCount > 100) {
            return false; // Too many requests
        }

        return true; // Request is allowed
    }
}
