package be.technifutur.demojwt.security;

import be.technifutur.demojwt.config.JwtProperties;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProperties properties;

    public JwtAuthenticationFilter(JwtProperties properties) {
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = request.getHeader("Authorization");

        if (token != null) {
            token = token.replace(properties.getPrefix(), "");
            try {
                // Is token valid?
                DecodedJWT jwt = JWT.require(Algorithm.HMAC512(properties.getSecret()))
                        .build()
                        .verify(token);
                // Token must not be expired
                if (jwt.getExpiresAt() != null && jwt.getExpiresAt().after(new Date())) {
                    // If so create authentication therefore next filters can work correctly
                    Authentication authentication = new UsernamePasswordAuthenticationToken(
                            jwt.getSubject(),
                            "", // No password
                            jwt.getClaim("roles").asList(String.class).stream()
                                    .map(SimpleGrantedAuthority::new)
                                    .toList()
                    );
                    // Put authentication in security context
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (JWTVerificationException ignored) {}
        }
        // Continue filter chain
        filterChain.doFilter(request, response);
    }
}
