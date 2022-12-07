package com.sashkou.authentication.service;

import com.sashkou.authentication.storage.CredentialsStorage;
import com.sashkou.authentication.storage.model.Credentials;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class BasicAuthService {

    private final CredentialsStorage credentialsStorage;

    public boolean auth(String header) {
        Credentials credentials = Utils.extractCredentialsOfBasicAuth(header);

        String user = credentials.getUser();
        String password = credentials.getPassword();

        return password.equals(credentialsStorage.getUserPassword(user));
    }
}
