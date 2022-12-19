package com.sashkou.authentication.service;

import com.sashkou.authentication.storage.model.Credentials;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JwtAuthService {

    private final JwtManager jwtManager;

    public String createToken(String header) {
        Credentials credentials = Utils.extractCredentialsOfBasicAuth(header);

        String user = credentials.getUser();

        return jwtManager.generate(user);
    }

    public boolean validateToken(String header) {
        String jwt = header.split(" ")[1];
        return jwtManager.validate(jwt);
    }
}
