package com.sashkou.authentication.service;

import com.sashkou.authentication.storage.CredentialsStorage;
import lombok.RequiredArgsConstructor;
import org.apache.tomcat.util.codec.binary.Base64;

@org.springframework.stereotype.Service
@RequiredArgsConstructor
public class Service {

    private final CredentialsStorage storage;

    public boolean handleAuth(String header) {
        if (header.contains("Basic")) {
            return handleBasicAuth(header);
        }

        return false;
    }

    private boolean handleBasicAuth(String header) {
        String encodedCredentials = header.split(" ")[1];
        String decodedCredentials = new String(Base64.decodeBase64(encodedCredentials));

        String user = decodedCredentials.split(":")[0];
        String password = decodedCredentials.split(":")[1];

        return password.equals(storage.getUserPassword(user));
    }
}
