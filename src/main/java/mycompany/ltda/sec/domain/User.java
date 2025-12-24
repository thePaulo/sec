package mycompany.ltda.sec.domain;

import jakarta.persistence.*;
import lombok.*;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Entity
@Table(name="usuarios")
@Getter
@EqualsAndHashCode(of = "id")
public class User implements UserDetails {

    @Id
    @GeneratedValue (generator = "gen_user_id",strategy = GenerationType.SEQUENCE)
    @SequenceGenerator(name = "gen_user_id", sequenceName = "seq_user_id",
            allocationSize = 1)
    private long id;

    private String nome;

    private String login;

    private String senha;

    private Role role;

    public User(String login, String encryptedPassword, Role role) {
        this.login=login;
        this.senha=encryptedPassword;
        this.role=role;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if(this.role == Role.ADMIN)return List.of(new SimpleGrantedAuthority("ROLE_ADMIN"),new SimpleGrantedAuthority("ROLE_USER"));
        return List.of(new SimpleGrantedAuthority("ROLE_USER"));
    }

    public User(){
        this.role = Role.USER;
    }

    @Override
    public @Nullable String getPassword() {
        return senha;
    }

    public long getId(){
        return id;
    }

    public Role getRole(){
        return role;
    }

    public String getSenha() {
        return senha;
    }

    @Override
    public String getUsername() {
        return login;
    }

    public String getLogin() {
        return login;
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }
}
