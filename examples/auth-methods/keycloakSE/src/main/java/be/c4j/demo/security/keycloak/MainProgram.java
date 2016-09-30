/*
 * Copyright 2014-2016 Rudy De Busscher (www.c4j.be)
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
 *
 */
package be.c4j.demo.security.keycloak;

import be.c4j.ee.security.credentials.authentication.keycloak.KeycloakAuthenticator;
import be.c4j.ee.security.credentials.authentication.keycloak.KeycloakUser;

/**
 *
 */
public class MainProgram {

    public static void main(String[] args) {
        KeycloakAuthenticator authenticator = new KeycloakAuthenticator("/keycloak.json");
        try {
            KeycloakUser user = authenticator.authenticate("test", "test");
            System.out.println(user.getFullName());

            authenticator.validate(user.getAccessToken().getToken());
            authenticator.validate(user.getAccessToken().getRefreshToken());
            authenticator.logout(user);

            // These will fail, because after logout.
            //authenticator.validate(user.getAccessToken().getToken());
            //authenticator.validate(user.getAccessToken().getRefreshToken());

        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
