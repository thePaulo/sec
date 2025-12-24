package mycompany.ltda.sec.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import mycompany.ltda.sec.config.TokenService;
import mycompany.ltda.sec.domain.User;
import mycompany.ltda.sec.dto.LoginRequest;
import mycompany.ltda.sec.dto.LoginResponse;
import mycompany.ltda.sec.dto.RegisterRequest;
import mycompany.ltda.sec.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService implements UserDetailsService {

    @Autowired
    private UserRepository repository;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final String ACCESS_TOKEN_COOKIE_NAME = "access_token";
    private static final String REFRESH_TOKEN_COOKIE_NAME = "refresh_token";
    private static final long ACCESS_TOKEN_MAX_AGE = 2 * 60 * 60; // 2 hours in seconds
    private static final long REFRESH_TOKEN_MAX_AGE = 7 * 24 * 60 * 60; // 7 days in seconds
    private static final boolean HTTP_ONLY = true;
    private static final boolean SECURE = false; // Set to false for localhost, true for production
    private static final String SAME_SITE = "Lax"; // Use "Lax" for better compatibility
    private static final String PATH = "/";

    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {

        User user = repository.findByLogin(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        return user;
    }

    public LoginResponse buildLoginResponse(User user,
                                            HttpServletResponse response) {

        String accessToken = tokenService.generateToken(user);
        String refreshToken = tokenService.generateRefreshToken(user);

        setAuthCookies(response, accessToken, refreshToken);

        return LoginResponse.fromUser(user);
    }

    public void register(RegisterRequest registerRequest) {
        if (repository.findByLogin(registerRequest.getLogin()) != null) {
            throw new RuntimeException("Username already exists");
        }

        String encryptedPassword =
                passwordEncoder.encode(registerRequest.getPassword());

        User user = new User(
                registerRequest.getLogin(),
                encryptedPassword,
                registerRequest.getRole()
        );

        repository.save(user);
    }

    public LoginResponse refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = extractTokenFromCookie(request, REFRESH_TOKEN_COOKIE_NAME);

        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new RuntimeException("Refresh token missing");
        }

        String login = tokenService.validateRefreshToken(refreshToken);
        if (login == null || login.isEmpty()) {
            throw new RuntimeException("Invalid refresh token");
        }

        User user = repository.findByLogin(login);
        if (user == null) {
            throw new RuntimeException("User not found");
        }

        var newAccessToken = tokenService.generateToken(user);

        setAccessTokenCookie(response, newAccessToken);

        return LoginResponse.fromUser(user);
    }

    public void logout(HttpServletResponse response) {
        clearAuthCookies(response);
    }

    private void setAuthCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        ResponseCookie accessTokenCookie = ResponseCookie.from(ACCESS_TOKEN_COOKIE_NAME, accessToken)
                .httpOnly(HTTP_ONLY)
                .secure(SECURE)
                .path(PATH)
                .maxAge(ACCESS_TOKEN_MAX_AGE)
                .sameSite(SAME_SITE)
                .build();

        ResponseCookie refreshTokenCookie = ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, refreshToken)
                .httpOnly(HTTP_ONLY)
                .secure(SECURE)
                .path(PATH)
                .maxAge(REFRESH_TOKEN_MAX_AGE)
                .sameSite(SAME_SITE)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
    }

    private void setAccessTokenCookie(HttpServletResponse response, String accessToken) {
        ResponseCookie accessTokenCookie = ResponseCookie.from(ACCESS_TOKEN_COOKIE_NAME, accessToken)
                .httpOnly(HTTP_ONLY)
                .secure(SECURE)
                .path(PATH)
                .maxAge(ACCESS_TOKEN_MAX_AGE)
                .sameSite(SAME_SITE)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
    }

    private void clearAuthCookies(HttpServletResponse response) {
        ResponseCookie accessTokenCookie = ResponseCookie.from(ACCESS_TOKEN_COOKIE_NAME, "")
                .httpOnly(HTTP_ONLY)
                .secure(SECURE)
                .path(PATH)
                .maxAge(0)
                .sameSite(SAME_SITE)
                .build();

        ResponseCookie refreshTokenCookie = ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, "")
                .httpOnly(HTTP_ONLY)
                .secure(SECURE)
                .path(PATH)
                .maxAge(0)
                .sameSite(SAME_SITE)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
    }

    private String extractTokenFromCookie(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(cookieName)) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    public String extractTokenFromHeader(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return null;
        }
        return authHeader.replace("Bearer ", "").trim();
    }

    public User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof User) {
            return (User) authentication.getPrincipal();
        }
        return null;
    }
}