package com.kiyotakeshi.jwtSample.service;

import com.kiyotakeshi.jwtSample.Domain.Role;
import com.kiyotakeshi.jwtSample.Domain.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(Long userId, String roleName);

    // void addRoleToUser(String userName, String roleName);
    User getUser(Long userId);

    User getUser(String userName);

    // User getUser(String userId);
    List<User> getUsers();

    List<Role> getRoles();
}
