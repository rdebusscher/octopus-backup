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

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class OctopusSSOPrincipalProvider implements SSOPrincipalProvider {

    @Override
    public OctopusSSOUser createSSOPrincipal(UserPrincipal userPrincipal) {
        Object token = userPrincipal.getUserInfo("token");
        if (token instanceof OctopusSSOUser) {
            // This is the case when we authenticate from SSOAuthenticatingFilter
            // We can just take that value, no need to recreate the object from scratch.
            return (OctopusSSOUser) token;
        }

        OctopusSSOUser ssoUser = new OctopusSSOUser();

        Object localId = userPrincipal.getInfo().get(OctopusSSOUser.LOCAL_ID);
        if (localId == null) {
            localId = userPrincipal.getId();
        }
        ssoUser.setLocalId(localId.toString());
        String externalId = userPrincipal.getExternalId();
        if (externalId == null) {
            externalId = userPrincipal.getId().toString();
        }
        ssoUser.setId(externalId);
        String name = userPrincipal.getFullName();
        if (name == null) {
            name = userPrincipal.getName();
        }
        ssoUser.setFullName(name);
        ssoUser.setFirstName(userPrincipal.getFirstName());
        ssoUser.setLastName(userPrincipal.getLastName());
        ssoUser.setEmail(userPrincipal.getEmail());
        ssoUser.setUserName(userPrincipal.getUserName());

        ssoUser.addUserInfo(userPrincipal.getInfo());
        return ssoUser;
    }
}
