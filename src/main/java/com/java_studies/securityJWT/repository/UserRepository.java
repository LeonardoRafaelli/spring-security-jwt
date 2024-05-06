package com.java_studies.securityJWT.repository;

import com.java_studies.securityJWT.user.UserDtls;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface UserRepository extends JpaRepository<UserDtls, Integer> {
    Optional<UserDtls> findByEmail(String email);
}
