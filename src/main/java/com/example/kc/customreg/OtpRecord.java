package com.example.kc.customreg;

import org.keycloak.common.util.Time;

public record OtpRecord(String phone, String code, int expiresAt) {
  public boolean isExpired() { return Time.currentTime() > expiresAt; }
}
