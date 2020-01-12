package com.example.shiro_jwt.myentity;

import org.apache.shiro.authc.AuthenticationToken;

/**
 *
 */
public class JwtToken implements AuthenticationToken {

    private String token;
    public String getToken() {
        return token;
    }
    public JwtToken(String token) {
        this.token = token;
    }

    @Override
    public Object getPrincipal() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return token;
    }
}