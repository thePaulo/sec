package mycompany.ltda.sec.controller;

import jakarta.validation.Valid;
import mycompany.ltda.sec.config.TokenService;
import mycompany.ltda.sec.domain.User;
import mycompany.ltda.sec.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody @Valid User user){
        var usernamePassword = new UsernamePasswordAuthenticationToken(user.getLogin(),user.getPassword());
        var auth = this.authenticationManager.authenticate(usernamePassword);

        var token  = tokenService.generateToken((User)auth.getPrincipal());

        return ResponseEntity.ok(token);
    }

    @PostMapping("/register")
    public ResponseEntity register(@RequestBody @Valid User user){
        if(this.userRepository.findByLogin(user.getLogin()) != null) return ResponseEntity.badRequest().build();

        String encryptedPassword = new BCryptPasswordEncoder().encode(user.getPassword());
        User newUser = new User(user.getLogin(),encryptedPassword,user.getRole());

        this.userRepository.save(newUser);

        return ResponseEntity.ok().build();
    }
}
