package com.example.kc.customreg;

import org.keycloak.models.KeycloakSession;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class OtpStore {
  // dev only: per-JVM maps
  private static final Map<String, OtpRecord> TXN = new ConcurrentHashMap<>();
  private static final Map<String, OtpRecord> RESET = new ConcurrentHashMap<>();

  public static void putTxn(KeycloakSession s, String id, OtpRecord rec){ TXN.put(id, rec); }
  public static OtpRecord getTxn(KeycloakSession s, String id){ return TXN.get(id); }
  public static void removeTxn(KeycloakSession s, String id){ TXN.remove(id); }

  public static void putReset(KeycloakSession s, String id, OtpRecord rec){ RESET.put(id, rec); }
  public static OtpRecord getReset(KeycloakSession s, String id){ return RESET.get(id); }
  public static void removeReset(KeycloakSession s, String id){ RESET.remove(id); }
}
