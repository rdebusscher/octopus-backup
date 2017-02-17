/*
 * Copyright 2014-2017 Rudy De Busscher (www.c4j.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.c4j.ee.security.logout.keycloak;

import be.c4j.ee.security.credentials.authentication.keycloak.KeycloakAuthenticator;
import be.c4j.ee.security.credentials.authentication.keycloak.KeycloakUser;
import be.c4j.ee.security.credentials.authentication.keycloak.config.KeycloakConfiguration;
import be.c4j.ee.security.event.LogoutEvent;
import be.c4j.ee.security.model.UserPrincipal;
import org.keycloak.adapters.KeycloakDeployment;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
public class KeycloakLogoutHandler {

    @Inject
    private KeycloakConfiguration keycloakConfiguration;

    private KeycloakAuthenticator authenticator;

    @PostConstruct
    public void init() {
        KeycloakDeployment oidcDeployment = keycloakConfiguration.getKeycloakDeployment();
        authenticator = new KeycloakAuthenticator(oidcDeployment);
    }

    public void preLogoutAction(@Observes LogoutEvent logoutEvent) {
        UserPrincipal userPrincipal = logoutEvent.getPrincipal();
        if (keycloakConfiguration.getKeycloakSingleLogout()) {

            //userprincipal == null !!
            KeycloakUser user = userPrincipal.getUserInfo("authenticationToken"); // TODO Use constant.

            authenticator.logout(user);
        }
    }

}
