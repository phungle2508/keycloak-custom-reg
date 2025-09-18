package com.example.kc.customreg;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import java.util.Random;

public final class Util {
    private static final Random R = new Random();

    public static String generate6() {
        return String.format("%06d", R.nextInt(1_000_000));
    }

    public static String normalizePhone(String raw) {
        if (raw == null) return null;
        String p = raw.replaceAll("\\s+", "");
        // very simple — adjust to your needs (+84 / 0 leading, etc.)
        if (!p.matches("^\\+?\\d{8,15}$")) return null;
        return p.startsWith("0") ? "+84" + p.substring(1) : p;
    }

    public static String realmAttr(KeycloakSession s, String k) {
        RealmModel r = s.getContext().getRealm();
        return r == null ? null : r.getAttribute(k);
    }

    public static int realmIntAttr(KeycloakSession s, String k, int def) {
        String v = realmAttr(s, k);
        if (v == null) return def;
        try { return Integer.parseInt(v); } catch (Exception e) { return def; }
    }
}
