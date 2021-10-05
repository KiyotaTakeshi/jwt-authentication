package com.kiyotakeshi.jwtSample;

import com.kiyotakeshi.jwtSample.Domain.Role;
import com.kiyotakeshi.jwtSample.Domain.User;
import com.kiyotakeshi.jwtSample.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class JwtSampleApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtSampleApplication.class, args);
	}

	@Bean
	CommandLineRunner run(UserService userService){
		return args -> {
			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_MANAGER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));

			User mike = userService.saveUser(new User(null, "Mike Popcorn", "mike", "passw0rd", new ArrayList<>()));
			User kanye = userService.saveUser(new User(null, "Kanye Lamar", "kanye", "passw1rd", new ArrayList<>()));
			User kendrick = userService.saveUser(new User(null, "Kendrick West", "kendrick", "passw2rd", new ArrayList<>()));

			userService.addRoleToUser(mike.getId(), "ROLE_USER");
			userService.addRoleToUser(kanye.getId(), "ROLE_USER");
			userService.addRoleToUser(kanye.getId(), "ROLE_MANAGER");
			userService.addRoleToUser(kendrick.getId(), "ROLE_ADMIN");
		};
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

}
