package com.example.restapiauthdemo.security.jwt;

import com.example.restapiauthdemo.services.UserDetailsImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import io.jsonwebtoken.*;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${restapiauthdemo.app.jwtSecret}")
    private String jwtSecret;

    @Value("${restapiauthdemo.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String generateJwtToken(Authentication authentication) {
        UserDetailsImpl user = (UserDetailsImpl) authentication.getPrincipal();
        Date expirationTime = new Date( (new Date()).getTime() + jwtExpirationMs);

        String JwtToken = Jwts.builder().setSubject(user.getUsername()).setIssuedAt(new Date())
                .setExpiration(expirationTime).signWith(SignatureAlgorithm.HS512, jwtSecret).compact();

        return JwtToken;
    }

    public String getUserNameFromJwtToken(String token) {
        String userName = Jwts.parser().setSigningKey(jwtSecret)
                .parseClaimsJws(token).getBody().getSubject();

        return userName;
    }

    public boolean validateJwtToken(String token) {

        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
}
