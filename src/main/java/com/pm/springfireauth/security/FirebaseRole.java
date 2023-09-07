package com.pm.springfireauth.security;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

@Data
@AllArgsConstructor
public class FirebaseRole implements GrantedAuthority {

    private String role;

    @Override
    public String getAuthority() {
        return this.role;
    }
}
