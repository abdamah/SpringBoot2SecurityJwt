package com.riigsoft.security.service;

import com.riigsoft.security.entity.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public interface IUserService {
    Integer saveUser(User user);

    Optional<User> findByUsername(String username);

    UserDetails loadUserByUsername(String username);
}
