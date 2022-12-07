package com.sashkou.authentication.service;

import com.sashkou.authentication.storage.SessionStorage;
import com.sashkou.authentication.storage.model.Credentials;
import com.sashkou.authentication.storage.model.Session;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class SessionAuthService {

    private final SessionStorage sessionStorage;

    public String createSession(String header) {
        Credentials credentials = Utils.extractCredentialsOfBasicAuth(header);
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
}
