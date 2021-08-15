package com.riigsoft.security.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.concurrent.TimeUnit;

@Component
public class JwtUtil {

    @Value("${app.secretKey}")
    private String secretKey;

    //1. Generate Token
    public String generateToken(String subject) {

        return
                Jwts.builder()
                        .setSubject(subject)
                        .setIssuer("RIIGSOFTABDALLAH")
                        .setIssuedAt(new Date(System.currentTimeMillis()))
                        .setExpiration(new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(15)))
                        .signWith(SignatureAlgorithm.HS512, secretKey.getBytes())
                        .compact();

    }

    //2. Read Claims
    public Claims getClaims(String token) {

        return Jwts.parser()
                .setSigningKey(secretKey.getBytes())
                .parseClaimsJws(token)
                .getBody();
    }

    //3. Read Exp Date
    public Date getExpDate(String token) {
        return getClaims(token).getExpiration();
    }

    //4.Get Subject / Username
    public String getUserName(String token) {
        return getClaims(token).getSubject();
    }

    //5.Validate Exp Date
    public boolean isTokenExp(String token) {
        return getExpDate(token).before(new Date(System.currentTimeMillis()));
    }

    //6. Validate user name in Token and database ,expDate
    public boolean validateToken(String token, String username) {
        return (username.equals(getUserName(token)) && !isTokenExp(token));
    }
}
