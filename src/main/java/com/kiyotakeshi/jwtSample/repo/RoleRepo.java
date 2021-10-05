package com.kiyotakeshi.jwtSample.repo;

import com.kiyotakeshi.jwtSample.Domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
