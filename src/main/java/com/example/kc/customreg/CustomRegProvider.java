package com.example.kc.customreg;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class CustomRegProvider implements RealmResourceProvider {
  private final KeycloakSession session;
  public CustomRegProvider(KeycloakSession session){ this.session = session; }

  @Override public Object getResource() {
    return new CustomRegResource(session);
  }
  @Override public void close() {}
}
