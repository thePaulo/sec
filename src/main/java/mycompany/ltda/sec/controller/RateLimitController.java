package mycompany.ltda.sec.controller;

import mycompany.ltda.sec.service.RedisRateLimiter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RateLimitController {

    @Autowired
    private RedisRateLimiter redisRateLimiter;

    @GetMapping("/api/resource")
    public String getResource(@RequestParam String userId) {
        if (!redisRateLimiter.tryAcquire(userId)) {
            return "Rate limit exceeded!";
        }
        return "Resource accessed successfully!";
    }
}
