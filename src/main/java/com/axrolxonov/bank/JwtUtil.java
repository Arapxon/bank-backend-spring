package com.axrolxonov.bank;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtil {

    // ⚠️ Base64 bo‘lishi SHART (kamida 32 byte)
    private static final String SECRET =
            "bXktc3VwZXItc2VjcmV0LWtleS0xMjM0NTY3ODkwMTIzNA==";

    private static final Key KEY = Keys.hmacShaKeyFor(
            Base64.getDecoder().decode(SECRET)
    );

    // ⏱ 1 kun
    private static final long EXPIRATION_TIME = 1000 * 60 * 60 * 24;

    // 🔑 TOKEN YARATISH
    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(
                        new Date(System.currentTimeMillis() + EXPIRATION_TIME)
                )
                .signWith(KEY, SignatureAlgorithm.HS256)
                .compact();
    }

    // 👤 USERNAME NI TOKEN ICHIDAN OLISH
    public String extractUsername(String token) {
        return getClaims(token).getSubject();
    }

    // ⏳ TOKEN MUDDATI O‘TGANMI?
    public boolean isTokenExpired(String token) {
        return getClaims(token)
                .getExpiration()
                .before(new Date());
    }

    // 🔍 TOKEN TEKSHIRISH (SIGNATURE + EXPIRATION)
    public boolean validateToken(String token) {
        try {
            return !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    // 🧠 ICHKI METHOD — CLAIMS O‘QISH
    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
