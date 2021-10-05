package com.kiyotakeshi.jwtSample.service;

import com.kiyotakeshi.jwtSample.Domain.Role;
import com.kiyotakeshi.jwtSample.Domain.User;
import com.kiyotakeshi.jwtSample.repo.RoleRepo;
import com.kiyotakeshi.jwtSample.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        User user = userRepo.findByUserName(userName);
        if (user == null) {
            log.error("User not found in the DB");
            throw new UsernameNotFoundException("User not found in the DB");
        } else {
            log.info("User found in the DB: {}", userName);
        }

        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });

        // public User(String username, String password, Collection<? extends GrantedAuthority> authorities) {
        return new org.springframework.security.core.userdetails.User(
                user.getUserName(),
                user.getPassword(),
                authorities
        );
    }

    @Override
    public User saveUser(User user) {
        log.info("Saving new user {} to DB", user.getName());
        user.setPassword((passwordEncoder.encode(user.getPassword())));
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving new role {} to DB", role.getName());
        return roleRepo.save(role);
    }

    @Override
    public void addRoleToUser(Long userId, String roleName) {
        log.info("Adding role {} to user {}", roleName, userId);
        var user = userRepo.findById(userId).orElseThrow();
        var role = roleRepo.findByName(roleName);
        user.getRoles().add(role);
    }

    @Override
    public User getUser(Long userId) {
        log.info("Fetching user {}", userId);
        return userRepo.findById(userId).orElseThrow();
    }

    @Override
    public User getUser(String userName) {
        log.info("Fetching user {}", userName);
        return userRepo.findByUserName(userName);
    }

//    @Override
//    public User getUser(String userName) {
//        log.info("Fetching user {}", userName);
//        return userRepo.findByUserName(userName);
//    }

    @Override
    public List<User> getUsers() {
        log.info("Fetching all users");
        return userRepo.findAll();
    }

    @Override
    public List<Role> getRoles() {
        log.info("Fetching all roles");
        return roleRepo.findAll();
    }
}
