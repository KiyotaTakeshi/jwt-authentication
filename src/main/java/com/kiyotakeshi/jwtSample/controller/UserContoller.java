package com.kiyotakeshi.jwtSample.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kiyotakeshi.jwtSample.Domain.Role;
import com.kiyotakeshi.jwtSample.Domain.User;
import com.kiyotakeshi.jwtSample.service.UserService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserContoller {
    private final UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsers() {
        return ResponseEntity.ok().body(userService.getUsers());
    }

    // @GetMapping("/users/")
    // public ResponseEntity<User> getUser(@RequestParam("userId") Long userId) {
    @GetMapping("/users/{userId}")
    public ResponseEntity<User> getUser(@PathVariable("userId") Long userId) {
        return ResponseEntity.ok().body(userService.getUser(userId));
    }

    @PostMapping("/users")
    public ResponseEntity<User> saveUser(@RequestBody User user) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/users").toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @GetMapping("/roles")
    public ResponseEntity<List<Role>> getRoles() {
        return ResponseEntity.ok().body(userService.getRoles());
    }

    @PostMapping("/roles")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/roles").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("/user/{userId}/roles")
    public ResponseEntity<?> addRoleToUser(@PathVariable("userId") Long userId, @RequestBody Role role) {
        userService.addRoleToUser(userId, role.getName());
        return ResponseEntity.ok().build();
    }

    @GetMapping("/token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response){
        // TODO:
//        String authorizationHeader = request.getHeader(AUTHORIZATION);
//        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
//            try {
//                String token = authorizationHeader.substring("Bearer ".length());
//                Algorithm algorithm = Algorithm.HMAC256("a20fd5b9-2bb9-4958-9f8c-b3fdf5f82157".getBytes());
//                JWTVerifier verifier = JWT.require(algorithm).build();
//                DecodedJWT decodedJWT = verifier.verify(token);
//                String username = decodedJWT.getSubject();
//                User user = userService.getUser(username);
//                String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
//                Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
//                stream(roles).forEach(role -> {
//                    authorities.add(new SimpleGrantedAuthority(role));
//                });
//                UsernamePasswordAuthenticationToken authenticationToken =
//                        new UsernamePasswordAuthenticationToken(username, null, authorities);
//                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
//            } catch (Exception ex) {
//                response.setHeader("error", ex.getMessage());
//                response.setStatus(FORBIDDEN.value());
//                // response.sendError(FORBIDDEN.value());
//                HashMap<String, String> error = new HashMap<>();
//                error.put("error_message", ex.getMessage());
//                response.setContentType(APPLICATION_JSON_VALUE);
//                new ObjectMapper().writeValue(response.getOutputStream(), error);
//            }
//        } else {
//            throw new RuntimeException("Refresh token is missing");
//        }
    }

//    @Data
//    class RoleToUserForm {
//        private String userName;
//        private String roleName;
//    }

//    @PostMapping("/role/addtouser")
//    public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm form) {
//        userService.addRoleToUser(form.getUserName(), form.getRoleName());
//        return ResponseEntity.ok().build();
//    }
}
