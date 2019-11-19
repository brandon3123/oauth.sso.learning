package com.oAuthLearning.oauth.sso.learning.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Date;

@RestController
public class ApplicationActions {

    @GetMapping("/user")
    public Principal getTime(Principal principal) {
        return principal;
    }
}
