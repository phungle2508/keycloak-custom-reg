package com.example.kc.customreg;

import okhttp3.*;

public final class SmsGateway {
    private static final MediaType JSON = MediaType.parse("application/json");

    static boolean send(org.keycloak.models.KeycloakSession session, String to, String msg) {
        String base   = Util.realmAttr(session,"sms.api.baseUrl");
        String token  = Util.realmAttr(session,"sms.api.key");
        String device = Util.realmAttr(session,"sms.deviceId");
        if (base == null || token == null || device == null) return false;

        OkHttpClient http = new OkHttpClient();
        String body = "{\"to\":\""+to+"\",\"message\":\""+msg+"\",\"deviceId\":\""+device+"\"}";
        Request req = new Request.Builder()
                .url(base + "/messages")
                .addHeader("Authorization", "Bearer " + token)
                .post(RequestBody.create(body, JSON))
                .build();
        try (Response res = http.newCall(req).execute()) {
            return res.isSuccessful();
        } catch (Exception e) {
            return false;
        }
    }
}
