package mycompany.ltda.sec.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import mycompany.ltda.sec.domain.User;
import mycompany.ltda.sec.dto.LoginRequest;
import mycompany.ltda.sec.dto.LoginResponse;
import mycompany.ltda.sec.dto.RegisterRequest;
import mycompany.ltda.sec.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    private final AuthenticationManager authenticationManager;

    public AuthController(AuthenticationManager authenticationManager,
                          AuthService authService) {
        this.authenticationManager = authenticationManager;
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody @Valid LoginRequest loginRequest,
            HttpServletResponse response) {

        Authentication authentication =
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                loginRequest.getLogin(),
                                loginRequest.getSenha()
                        )
                );

        System.out.println("Authentication successful for user: " + loginRequest.getLogin());

        User user = (User) authentication.getPrincipal();

        LoginResponse loginResponse =
                authService.buildLoginResponse(user, response);

        System.out.println("User role: " + (user.getRole() != null ? user.getRole().name() : "null"));

        return ResponseEntity.ok(loginResponse);
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody @Valid RegisterRequest registerRequest) {
        try {
            authService.register(registerRequest);
            return ResponseEntity.ok("User registered successfully");
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(e.getMessage());
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        authService.logout(response);
        return ResponseEntity.ok("Logged out successfully");
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request,
                                          HttpServletResponse response) {
        try {
            LoginResponse loginResponse = authService.refreshToken(request, response);
            return ResponseEntity.ok(loginResponse);
        } catch (Exception e) {
            return ResponseEntity.status(401)
                    .body(e.getMessage());
        }
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