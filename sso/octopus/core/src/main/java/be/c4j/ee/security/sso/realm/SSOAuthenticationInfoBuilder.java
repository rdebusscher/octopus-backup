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
package be.c4j.ee.security.sso.realm;

import be.c4j.ee.security.OctopusConstants;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.sso.OctopusSSOUser;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.SimpleAuthenticationInfo;

import static be.c4j.ee.security.realm.AuthenticationInfoBuilder.DEFAULT_REALM;

/**
 *
 */

public class SSOAuthenticationInfoBuilder {


    private AuthenticationInfo authenticationInfo;

    public SSOAuthenticationInfoBuilder(OctopusSSOUser octopusSSOUser) {
        buildInfo(octopusSSOUser);
    }

    private void buildInfo(OctopusSSOUser octopusSSOUser) {


        UserPrincipal principal = new UserPrincipal(octopusSSOUser.getId(), octopusSSOUser.getUserName(), octopusSSOUser.getName());
        principal.addUserInfo(OctopusConstants.EMAIL, octopusSSOUser.getEmail());  // Make sure the email is within the userInfo
        principal.addUserInfo(OctopusConstants.LOCAL_ID, octopusSSOUser.getLocalId());
        principal.addUserInfo(octopusSSOUser.getUserInfo());
        principal.addUserInfo(OctopusConstants.FULL_NAME, octopusSSOUser.getFullName());
        authenticationInfo = new SimpleAuthenticationInfo(principal, null, DEFAULT_REALM);

    }

    public AuthenticationInfo getAuthenticationInfo() {
        return authenticationInfo;
    }

}
