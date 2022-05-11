package be.technifutur.demojwt.service;

import be.technifutur.demojwt.config.JwtProperties;
import be.technifutur.demojwt.model.form.LoginForm;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class LoginService {

    // Could use @Autowired instead of constructor but constructor can be more secured since I can use final key-word
    private final AuthenticationManager authenticationManager;
    private final JwtProperties properties;

    public LoginService(AuthenticationManager authenticationManager, JwtProperties properties) {
        this.authenticationManager = authenticationManager;
        this.properties = properties;
    }

    // Get a token (JWT is basically a String)
    public String login(LoginForm form) {
        // Create authentication
        Authentication authentication = new UsernamePasswordAuthenticationToken(form.getUsername(), form.getPassword());
        // Is user connected?
        authentication = authenticationManager.authenticate(authentication); // We'll handle exceptions in ControllerAdvisor
        return JWT.create()
                .withSubject(form.getUsername())
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + properties.getExpires()))
                .withClaim("roles", authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .sign(Algorithm.HMAC512(properties.getSecret()));
    }
}
