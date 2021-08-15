package com.riigsoft.security.service.impl;

import com.riigsoft.security.entity.User;
import com.riigsoft.security.entity.UserDetail;
import com.riigsoft.security.repo.UserRepository;
import com.riigsoft.security.service.IUserService;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService implements IUserService{

    @Autowired
    private UserRepository repo;
    @Autowired
    private BCryptPasswordEncoder pwdEncoder;
    @Autowired
    private UserDetail userdetail;

    @Override
    public Integer saveUser(User user) {

        //Encode Password
        user.setPassword(pwdEncoder.encode(user.getPassword()));

        return repo.save(user).getId();
    }

    @Override
    public Optional<User> findByUsername(String username) {
        return repo.findByUsername(username);
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        return userdetail.loadUserByUsername(username);
    }


}
