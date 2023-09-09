package com.pm.springfireauth.security;

import com.google.firebase.auth.FirebaseAuth;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class FirebaseFilter extends OncePerRequestFilter {
    private final FireAuthManager fireAuthManager;

    public FirebaseFilter(FireAuthManager fireAuthManager) {

        this.fireAuthManager = fireAuthManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = fireAuthManager.authenticate(new FireAuthToken(extractToken(request)));
        if (authentication == null) {
            response.sendError(401);
            return;
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        String auth = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (auth == null || auth.isBlank()) {
            return null;
        }
        return auth.split(" ")[1];
    }
}
