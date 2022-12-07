package com.sashkou.authentication.service;

import com.sashkou.authentication.storage.CredentialsStorage;
import com.sashkou.authentication.storage.SessionStorage;
import com.sashkou.authentication.storage.model.Credentials;
import com.sashkou.authentication.storage.model.Session;
import lombok.RequiredArgsConstructor;
import org.apache.tomcat.util.codec.binary.Base64;

import java.time.Instant;
import java.util.Optional;

@org.springframework.stereotype.Service
@RequiredArgsConstructor
public class Service {

    private final CredentialsStorage credentialsStorage;
    private final SessionStorage sessionStorage;

    public boolean doBasicAuth(String header) {
        Credentials credentials = extractCredentialsOfBasicAuth(header);

        String user = credentials.getUser();
        String password = credentials.getPassword();

        return password.equals(credentialsStorage.getUserPassword(user));
    }

    public String createSession(String header) {
        Credentials credentials = extractCredentialsOfBasicAuth(header);
        String user = credentials.getUser();

        return sessionStorage.createSession(user);
    }

    public boolean validateSession(String header) {
        String sessionId = header.split(" ")[1];
        Optional<Session> maybeSession = sessionStorage.getSession(sessionId);
        if (maybeSession.isEmpty()) {
            return false;
        }

        Session session = maybeSession.get();
        return session.getExpiresAt().isAfter(Instant.now());
    }

    private Credentials extractCredentialsOfBasicAuth(String header) {
        String encodedCredentials = header.split(" ")[1];
        String decodedCredentials = new String(Base64.decodeBase64(encodedCredentials));

        String user = decodedCredentials.split(":")[0];
        String password = decodedCredentials.split(":")[1];

        return new Credentials(user, password);
    }
}
