package mycompany.ltda.sec.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import mycompany.ltda.sec.config.TokenService;
import mycompany.ltda.sec.domain.User;
import mycompany.ltda.sec.dto.LoginRequest;
import mycompany.ltda.sec.dto.LoginResponse;
import mycompany.ltda.sec.dto.RegisterRequest;
import mycompany.ltda.sec.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @RequestBody LoginRequest request,
            HttpServletResponse response) {

        try {
            // Authenticate user
            var authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getLogin(),
                            request.getSenha()
                    )
            );

            var user = (User) authentication.getPrincipal();

            // Generate tokens
            String accessToken = tokenService.generateToken(user);
            String refreshToken = tokenService.generateRefreshToken(user);

            // Set access token in HTTP-only cookie
            Cookie accessTokenCookie = new Cookie("accessToken", accessToken);
            accessTokenCookie.setHttpOnly(true);
            accessTokenCookie.setSecure(true); // Only over HTTPS
            accessTokenCookie.setPath("/");
            accessTokenCookie.setMaxAge(15 * 60); // 15 minutes
            accessTokenCookie.setAttribute("SameSite", "Strict");
            response.addCookie(accessTokenCookie);

            // Set refresh token in HTTP-only cookie
            Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setSecure(true);
            refreshTokenCookie.setPath("/auth/refresh"); // Only sent to refresh endpoint
            refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
            refreshTokenCookie.setAttribute("SameSite", "Strict");
            response.addCookie(refreshTokenCookie);

            return ResponseEntity.ok(new LoginResponse(
                    user.getId(),
                    user.getUsername()
            ));

        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new LoginResponse(null, null));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<Void> refresh(
            @CookieValue(name = "refreshToken", required = false) String refreshToken,
            HttpServletResponse response) {

        if (refreshToken == null || tokenService.validateToken(refreshToken) == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String username = tokenService.getSubject(refreshToken);
        User user = (User)authService.loadUserByUsername(username);

        // Generate new access token
        String newAccessToken = tokenService.generateToken(user);

        Cookie accessTokenCookie = new Cookie("accessToken", newAccessToken);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(true);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(15 * 60);
        accessTokenCookie.setAttribute("SameSite", "Strict");
        response.addCookie(accessTokenCookie);

        return ResponseEntity.ok().build();
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        // Clear cookies
        Cookie accessTokenCookie = new Cookie("accessToken", null);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(true);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(0);
        response.addCookie(accessTokenCookie);

        Cookie refreshTokenCookie = new Cookie("refreshToken", null);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setPath("/auth/refresh");
        refreshTokenCookie.setMaxAge(0);
        response.addCookie(refreshTokenCookie);

        return ResponseEntity.ok().build();
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser() {
        try {
            var user = authService.getCurrentUser();
            if (user == null) {
                return ResponseEntity.status(401).body("Not authenticated");
            }
            return ResponseEntity.ok(LoginResponse.fromUser(user));
        } catch (Exception e) {
            return ResponseEntity.status(401).body("Not authenticated");
        }
    }
}