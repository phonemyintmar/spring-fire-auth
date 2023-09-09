package com.pm.springfireauth.security;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
public class FireAuthManager implements AuthenticationManager {

    private final FirebaseAuth firebaseAuth;

    public FireAuthManager(FirebaseAuth firebaseAuth) {
        this.firebaseAuth = firebaseAuth;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String token = (String) authentication.getCredentials();
        try {
            FirebaseToken firebaseToken = firebaseAuth.verifyIdToken(token);
            List<String> roles = getRoles(firebaseToken);
            if (roles == null) {
                return new FireAuthToken(token, firebaseToken, null);
            }
            List<FirebaseRole> firebaseRoles = new ArrayList<>();
            StringBuilder builder = new StringBuilder();
            for (String role : roles) {
                builder.append("ROLE_");
                builder.append(role);
                firebaseRoles.add(new FirebaseRole(builder.toString()));
            }
            return new FireAuthToken(token, firebaseToken, firebaseRoles);
        } catch (Exception e) {
            log.error("Wrong authentication : {}", e.getMessage());
            return null;
        }
    }

    private List<String> getRoles(FirebaseToken firebaseToken) {
        try {
            return (List<String>) firebaseToken.getClaims().get("role");
        } catch (Exception e) {
            log.error("Error in getting roles {}", e.getMessage());
            return null;
        }
    }
}
