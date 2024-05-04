package com.java_studies.securityJWT.repository;

import com.java_studies.securityJWT.user.UserDtls;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserDetails, Integer> {
    Optional<UserDetails> findByEmail(String email);
}
