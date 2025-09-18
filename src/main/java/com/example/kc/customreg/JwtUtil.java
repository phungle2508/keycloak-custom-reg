package com.example.kc.customreg;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

public final class JwtUtil {
    private static final ObjectMapper M = new ObjectMapper();

    public static String issue(KeycloakSession session, Map<String,Object> claims, int ttlSeconds) {
        try {
            RealmModel realm = session.getContext().getRealm();
            long now = Instant.now().getEpochSecond();
            long exp = now + ttlSeconds;

            Map<String,Object> header = Map.of("alg","HS256","typ","JWT");
            Map<String,Object> payload = new HashMap<>(claims);
            payload.putIfAbsent("iat", now);
            payload.put("exp", exp);
            payload.put("iss", realm.getName());

            String h = Base64Url.encode(M.writeValueAsBytes(header));
            String p = Base64Url.encode(M.writeValueAsBytes(payload));
            String input = h + "." + p;

            SignatureProvider sp = session.getProvider(SignatureProvider.class, Algorithm.HS256);
            SignatureSignerContext signer = sp.signer();
            byte[] sig = signer.sign(input.getBytes(StandardCharsets.UTF_8));
            String s = Base64Url.encode(sig);

            return input + "." + s;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String,Object> verifyRequire(KeycloakSession session, String token, String key, String value) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) throw new RuntimeException("bad token");

            // verify signature
            SignatureProvider sp = session.getProvider(SignatureProvider.class, Algorithm.HS256);
            byte[] inputBytes = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8);
            byte[] sigBytes = Base64Url.decode(parts[2]);
            // re-sign using realm signer and compare
            SignatureSignerContext signer = sp.signer();
            byte[] expectedSig = signer.sign(inputBytes);
            if (!java.util.Arrays.equals(expectedSig, sigBytes)) throw new RuntimeException("bad sig");

            Map<String,Object> payload = M.readValue(Base64Url.decode(parts[1]), Map.class);
            long exp = ((Number)payload.get("exp")).longValue();
            if (Instant.now().getEpochSecond() > exp) throw new RuntimeException("expired");

            if (!value.equals(payload.get(key))) throw new RuntimeException("bad typ");
            return payload;
        } catch (Exception e) {
            throw new WebApplicationException(Response.status(401).entity(Map.of("error","invalid_token")).build());
        }
    }
}
