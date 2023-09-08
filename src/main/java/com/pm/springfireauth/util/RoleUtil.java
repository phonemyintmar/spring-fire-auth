package com.pm.springfireauth.util;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.pm.springfireauth.security.FirebaseRole;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@Slf4j
public class RoleUtil {

    private final FirebaseAuth firebaseAuth;

    public RoleUtil(FirebaseAuth firebaseAuth) {
        this.firebaseAuth = firebaseAuth;
    }

    public boolean addRole(String role) {
        Map<String, Object> map = new HashMap<>();
        FirebaseRole firebaseRole = new FirebaseRole(role);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>(authentication.getAuthorities());
        grantedAuthorities.add(firebaseRole);

        map.put("role", grantedAuthorities);
        Map<String, String> authMap = (Map<String, String>) authentication.getPrincipal();
        try {
            firebaseAuth.setCustomUserClaims(authMap.get("uid"), map);
            return true;
        } catch (FirebaseAuthException e) {
            log.error("Error in adding role with cause : {}", e.getMessage());
            return false;
        }
    }
}
