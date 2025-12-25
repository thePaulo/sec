package mycompany.ltda.sec.dto;

import mycompany.ltda.sec.domain.Role;
import mycompany.ltda.sec.domain.User;

public class LoginResponse {
    private Long id;
    private String username;
    private Role role;

    // Constructors
    public LoginResponse() {}

    public LoginResponse(Long id, String username) {
        this.id = id;
        this.username = username;
    }

    public static LoginResponse fromUser(User user) {
        return new LoginResponse(
                user.getId(),
                user.getLogin()
        );
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public Role getRole() { return role; }
    public void setRole(Role role) { this.role = role; }

    public static LoginResponse createLoginResponse(User user) {
        return new LoginResponse(
                user.getId(),
                user.getLogin()
        );
    }
}