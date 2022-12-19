package com.sashkou.authentication.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/secret")
public class Controller {

    @GetMapping("/basic-auth")
    public String getBasicAuthSecret() {
        return "Secret protected by basic authentication: " + UUID.randomUUID();
    }

    @GetMapping("/session-auth")
    public String getSessionAuthSecret() {
        return "Secret protected by session authentication: " + UUID.randomUUID();
    }

    @GetMapping("/jwt-auth")
    public String getJwtAuthSecret() {
        return "Secret protected by jwt authentication: " + UUID.randomUUID();
    }

}