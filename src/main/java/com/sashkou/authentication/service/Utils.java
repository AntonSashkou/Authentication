package com.sashkou.authentication.service;

import com.sashkou.authentication.storage.model.Credentials;
import lombok.experimental.UtilityClass;
import org.apache.tomcat.util.codec.binary.Base64;

@UtilityClass
public class Utils {

    public Credentials extractCredentialsOfBasicAuth(String header) {
        String encodedCredentials = header.split(" ")[1];
        String decodedCredentials = new String(Base64.decodeBase64(encodedCredentials));

        String user = decodedCredentials.split(":")[0];
        String password = decodedCredentials.split(":")[1];

        return new Credentials(user, password);
    }
}
