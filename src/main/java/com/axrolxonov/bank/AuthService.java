package com.axrolxonov.bank;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserRepository repo;
    private final JwtUtil jwt;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public AuthService(UserRepository repo, JwtUtil jwt) {
        this.repo = repo;
        this.jwt = jwt;
    }

    public String register(String username, String password) {
        if (repo.findByUsername(username).isPresent()) {
            return "USER EXISTS ❌";
        }

        User u = new User();
        u.setUsername(username);
        u.setPassword(encoder.encode(password));
        repo.save(u);

        return "REGISTERED ✅";
    }

    public String login(String username, String password) {
        User u = repo.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("USER NOT FOUND"));

        if (!encoder.matches(password, u.getPassword())) {
            throw new RuntimeException("WRONG PASSWORD");
        }

        return jwt.generateToken(username);
    }
}
