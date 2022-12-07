package com.sashkou.authentication.storage.model;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.Instant;

@Data
@AllArgsConstructor
public class Session {
    private String id;
    private String user;
    private Instant createdAt;
    private Instant expiresAt;
}
