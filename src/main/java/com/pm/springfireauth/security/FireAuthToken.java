package com.pm.springfireauth.security;

import com.google.firebase.auth.FirebaseToken;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import javax.security.auth.Subject;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class FireAuthToken extends AbstractAuthenticationToken {

    private final String accessToken;

    private FirebaseToken firebaseToken;


    public FireAuthToken(String accessToken, FirebaseToken firebaseToken, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);

        this.accessToken = accessToken;
        this.firebaseToken = firebaseToken;
        setAuthenticated(true);
        setDetails(firebaseToken);
    }

    public FireAuthToken(String accessToken) {
        super(null);
        this.accessToken = accessToken;
        setAuthenticated(false);
    }

    @Override
    public Object getCredentials() {
        return this.accessToken;
    }

    @Override
    public Object getPrincipal() {
        Map<String,String> authMap = new HashMap<>();
        authMap.put("name", firebaseToken.getName());
        authMap.put("email", firebaseToken.getName());
        authMap.put("uid", firebaseToken.getUid());
//        String userName = firebaseToken.getName();
//        if (userName == null || userName.isBlank()) return firebaseToken.getEmail();
//        return firebaseToken.getName();
        return authMap;
    }

    public Map<String, Object> getCustomClaims() {
        return firebaseToken.getClaims();
    }

    @Override
    public Object getDetails() {
        return firebaseToken.getClaims();
    }


    @Override
    public boolean implies(Subject subject) {
        return super.implies(subject);
    }
}
