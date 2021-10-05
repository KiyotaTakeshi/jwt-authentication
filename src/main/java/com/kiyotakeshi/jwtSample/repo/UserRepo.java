package com.kiyotakeshi.jwtSample.repo;

import com.kiyotakeshi.jwtSample.Domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepo extends JpaRepository<User, Long> {

    Optional<User> findById(Long id);

    User findByUsername(String username);
}
