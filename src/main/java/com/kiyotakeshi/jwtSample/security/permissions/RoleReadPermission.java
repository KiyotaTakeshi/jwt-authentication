package com.kiyotakeshi.jwtSample.security.permissions;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("hasAnyAuthority('ROLE_MANAGER','ROLE_ADMIN')")
public @interface RoleReadPermission {
}
