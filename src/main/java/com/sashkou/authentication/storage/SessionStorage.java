package com.sashkou.authentication.storage;

import com.sashkou.authentication.storage.model.Session;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public class SessionStorage {

    private static final List<Session> sessions = new ArrayList<>();

    public String createSession(String user) {
        String id = UUID.randomUUID().toString();
        Instant createdAt = Instant.now();
        Instant expireAt = createdAt.plus(12, ChronoUnit.HOURS);

        Session session = new Session(id, user, createdAt, expireAt);
        sessions.add(session);

        return id;
    }

    public Optional<Session> getSession(String id) {
        return sessions.stream()
                .filter(session -> id.equals(session.getId()))
                .findFirst();
    }
}
