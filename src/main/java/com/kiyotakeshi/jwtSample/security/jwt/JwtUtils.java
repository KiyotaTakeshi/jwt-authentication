package com.kiyotakeshi.jwtSample.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.kiyotakeshi.jwtSample.Domain.Role;
import com.kiyotakeshi.jwtSample.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.HashMap;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtUtils {

    @Value("${kiyotakeshi.jwtSecret}")
    private String jwtSecret;

    @Value("${kiyotakeshi.jwtExpirationMs}")
    private int jwtExpirationMs;

    private final UserService userService;

    public JwtUtils(UserService userService) {
        this.userService = userService;
    }

    public HashMap<String, String> generateJwtToken(HttpServletRequest request, User user) {
        Algorithm algorithm = Algorithm.HMAC256(jwtSecret.getBytes());
        String accessToken = JWT.create()
                .withSubject(user.getUsername())
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);

        String refreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);

        HashMap<String, String> tokens = new HashMap<>();
        tokens.put("access_token",accessToken);
        tokens.put("refresh_token",refreshToken);
        log.info("token generated");
        return tokens;
    }

    public HashMap<String, String> regenerateJwtToken(HttpServletRequest request, String authorizationHeader) {
        Algorithm algorithm = Algorithm.HMAC256(jwtSecret.getBytes());
        String refreshToken = authorizationHeader.substring("Bearer ".length());
        DecodedJWT decodedJWT = decodeJwtToken(refreshToken);

        String username = decodedJWT.getSubject();
        com.kiyotakeshi.jwtSample.Domain.User user = userService.getUser(username);

        String accessToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                .sign(algorithm);

        HashMap<String, String> tokens = new HashMap<>();
        tokens.put("access_token",accessToken);
        tokens.put("refresh_token",refreshToken);
        return tokens;
    }

    public DecodedJWT decodeJwtToken(String token) {
        Algorithm algorithm = Algorithm.HMAC256(jwtSecret.getBytes());
        JWTVerifier verifier = JWT.require(algorithm).build();
        return verifier.verify(token);
    }
}
