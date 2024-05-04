package com.java_studies.securityJWT.auth;

import com.java_studies.securityJWT.config.jwt.JwtService;
import com.java_studies.securityJWT.repository.UserRepository;
import com.java_studies.securityJWT.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepo;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    // Save new user in the database and return the new generated token
    public AuthenticationResponse register(RegisterRequest request) {
        // Build new user
        var user = User.builder()
                .username(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Role.USER.toString())
                .build();

        userRepo.save(user);

        // Build new JWT token
        var jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }


    public AuthenticationResponse authentication(AuthenticationRequest request) {
        return null;
    }
}
