package com.sashkou.authentication.service;

import org.json.JSONObject;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;

@Component
public class JwtManager {

    private static final String JWT_HEADER = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    private static final String ISSUER = "anton.sashkou";
    private static final String SECRET_KEY = "SECRET";
    private static final int EXPIRY_DAYS = 90;

    public String generate(String subject) {
        String encodedHeader = encode(JWT_HEADER);

        String payload = createPayload(subject);
        String encodedPayload = encode(payload);

        String signature = sign(encodedHeader + "." + encodedPayload);

        return encodedHeader + "." + encodedPayload + "." + signature;
    }

    public boolean validate(String jwt) {
        String[] jwtParts = jwt.split("\\.");
        String encodedHeader = jwtParts[0];
        String encodedPayload = jwtParts[1];
        String signature = jwtParts[2];

        JSONObject payload = new JSONObject(decode(encodedPayload));

        boolean notExpired = payload.getLong("exp") > (LocalDateTime.now().toEpochSecond(ZoneOffset.UTC));
        boolean notHacked = signature.equals(sign(encodedHeader + "." + encodedPayload));

        return notExpired && notHacked;
    }

    private String createPayload(String subject) {
        JSONObject payload = new JSONObject();

        long expirationTime = calculateExpirationTime();

        payload.put("exp", expirationTime);
        payload.put("iss", ISSUER);
        payload.put("sub", subject);

        return payload.toString();
    }

    private long calculateExpirationTime() {
        LocalDateTime expiryDate = LocalDateTime.now().plusDays(EXPIRY_DAYS);
        return expiryDate.toEpochSecond(ZoneOffset.UTC);
    }

    private String encode(String encodeCandidate) {
        byte[] bytes = encodeCandidate.getBytes();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String decode(String decodeCandidate) {
        return new String(Base64.getUrlDecoder().decode(decodeCandidate));
    }

    private String sign(String data) {
        try {
            byte[] hash = SECRET_KEY.getBytes(StandardCharsets.UTF_8);

            Mac sha256Hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(hash, "HmacSHA256");
            sha256Hmac.init(secretKey);

            byte[] signedBytes = sha256Hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return encode(Arrays.toString(signedBytes));
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new RuntimeException("Can't generate token");
        }
    }
}
