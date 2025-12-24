package mycompany.ltda.sec.config;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import mycompany.ltda.sec.domain.User;
import mycompany.ltda.sec.domain.Role;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {

    @Value("${api.security.token.secret}")
    private String secret;

    @Value("${api.security.token.refresh-secret:default-refresh-secret}")
    private String refreshSecret;

    public String generateToken(User user) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);

            // Create JWT builder
            var jwtBuilder = JWT.create()
                    .withIssuer("auth-api")
                    .withSubject(user.getLogin())
                    .withExpiresAt(genAccessTokenExpirationDate());

            // Add role claim only if role is not null
            if (user.getRole() != null) {
                jwtBuilder.withClaim("role", user.getRole().name());
            }

            // Add userId claim only if id is not null
            if (user.getId() != 0l) {
                jwtBuilder.withClaim("userId", user.getId());
            }

            String token = jwtBuilder.sign(algorithm);
            return token;
        } catch (JWTCreationException e) {
            throw new RuntimeException("Error While Generating Token", e);
        }
    }

    public String generateRefreshToken(User user) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(refreshSecret);
            String token = JWT.create()
                    .withIssuer("auth-api")
                    .withSubject(user.getLogin())
                    .withClaim("type", "refresh")
                    .withExpiresAt(genRefreshTokenExpirationDate())
                    .sign(algorithm);
            return token;
        } catch (JWTCreationException e) {
            throw new RuntimeException("Error While Generating Refresh Token", e);
        }
    }

    public String validateToken(String token) {
        return validateToken(token, secret);
    }

    public String validateRefreshToken(String token) {
        return validateToken(token, refreshSecret);
    }

    private String validateToken(String token, String secretKey) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secretKey);
            return JWT.require(algorithm)
                    .withIssuer("auth-api")
                    .build()
                    .verify(token)
                    .getSubject();
        } catch (JWTVerificationException e) {
            return null;
        }
    }

    // Optional: Method to extract role from token
    public String extractRoleFromToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.require(algorithm)
                    .withIssuer("auth-api")
                    .build()
                    .verify(token)
                    .getClaim("role")
                    .asString();
        } catch (JWTVerificationException e) {
            return null;
        }
    }

    private Instant genAccessTokenExpirationDate() {
        // 2 hours from now
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }

    private Instant genRefreshTokenExpirationDate() {
        // 7 days from now
        return LocalDateTime.now().plusDays(7).toInstant(ZoneOffset.of("-03:00"));
    }
}