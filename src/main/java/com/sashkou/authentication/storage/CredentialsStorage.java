package com.sashkou.authentication.storage;

import org.springframework.stereotype.Repository;

import java.util.Map;

@Repository
public class CredentialsStorage {

    private static final Map<String, String> credentials = Map.of("user", "password");

    public String getUserPassword(String user) {
        return credentials.get(user);
    }
}
