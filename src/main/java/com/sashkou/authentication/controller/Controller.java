package com.sashkou.authentication.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/secret")
public class Controller {

    @GetMapping
    public String getSecret() {
        return UUID.randomUUID().toString();
    }

}