package com.example.kc.customreg;

import okhttp3.*;
import org.keycloak.models.KeycloakSession;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class SmsGateway {
    private static final MediaType JSON = MediaType.parse("application/json");

    static boolean send(KeycloakSession session, String to, String msg) {
        String base = Util.realmAttr(session, "sms.api.baseUrl"); // https://sms-gate.app
        String user = Util.realmAttr(session, "sms.api.username");
        String pass = Util.realmAttr(session, "sms.api.password");
        String device = Util.realmAttr(session, "sms.deviceId");
        String sim = Util.realmAttr(session, "sms.simNumber");
        String ttlStr = Util.realmAttr(session, "sms.otp.ttlSeconds");

        if (base == null || user == null || pass == null || device == null) {
            return false;
        }

        int ttl = 90;
        try {
            ttl = Integer.parseInt(ttlStr);
        } catch (Exception ignored) {
        }

        String basic = Base64.getEncoder()
                .encodeToString((user + ":" + pass).getBytes(StandardCharsets.UTF_8));

        String body = """
                {
                  "textMessage": { "text": "%s" },
                  "deviceId": "%s",
                  "phoneNumbers": ["%s"],
                  "simNumber": %s,
                  "ttl": %d,
                  "skipPhoneValidation": true
                }
                """.formatted(msg, device, to, sim != null ? sim : "1", ttl);

        OkHttpClient http = new OkHttpClient();
        Request req = new Request.Builder()
                .url(base + "/api/3rdparty/v1/messages")
                .addHeader("Authorization", "Basic " + basic)
                .addHeader("Content-Type", "application/json")
                .post(RequestBody.create(body, JSON))
                .build();

        try (Response res = http.newCall(req).execute()) {
            return res.isSuccessful();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
