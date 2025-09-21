package com.example.kc.customreg;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class CustomRegProviderFactory implements RealmResourceProviderFactory {
    public static final String ID = "customreg"; // URL segment

    @Override public RealmResourceProvider create(KeycloakSession session) {
        return new CustomRegProvider(session);
    }
    @Override public void init(org.keycloak.Config.Scope config) {}
    @Override public void postInit(org.keycloak.models.KeycloakSessionFactory factory) {}
    @Override public void close() {}
    @Override public String getId() { return ID; }
}
