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
package be.c4j.ee.security.sso.server;

import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.SSOPrincipalProvider;
import be.c4j.ee.security.sso.server.token.SSOTokenProvider;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.UUID;

/**
 *
 */
@ApplicationScoped
public class OctopusSSOPrincipalProvider implements SSOPrincipalProvider {

    @Inject
    private SSOTokenProvider ssoTokenProvider;

    @Override
    public Object createSSOPrincipal(UserPrincipal userPrincipal) {
        OctopusSSOUser ssoUser = new OctopusSSOUser();
        ssoUser.setLocalId(userPrincipal.getId().toString());
        String externalId = userPrincipal.getExternalId();
        if (externalId == null) {
            externalId = userPrincipal.getId().toString();
        }
        ssoUser.setId(externalId);
        ssoUser.setFullName(userPrincipal.getFullName());
        ssoUser.setFirstName(userPrincipal.getFirstName());
        ssoUser.setLastName(userPrincipal.getLastName());
        ssoUser.setEmail(userPrincipal.getEmail());
        ssoUser.setUserName(userPrincipal.getUserName());
        ssoUser.setToken(ssoTokenProvider.getTokenPrefix() + UUID.randomUUID().toString());

        ssoUser.addUserInfo(userPrincipal.getInfo());
        return ssoUser;
    }
}
