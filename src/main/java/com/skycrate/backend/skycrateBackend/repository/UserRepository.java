package com.skycrate.backend.skycrateBackend.repository;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import com.skycrate.backend.skycrateBackend.models.User;
public interface UserRepository extends CrudRepository<User,Integer> {
    Optional<User> findByEmail(String email);
    /*
    // might use later
     Optional<User> findByVerificationCode(String verificationCode);
     */

}
