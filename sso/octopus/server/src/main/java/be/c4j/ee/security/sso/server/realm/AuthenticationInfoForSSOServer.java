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
package be.c4j.ee.security.sso.server.realm;

import be.c4j.ee.security.realm.OctopusDefinedAuthenticationInfo;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.realm.SSOAuthenticationInfoBuilder;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class AuthenticationInfoForSSOServer implements OctopusDefinedAuthenticationInfo {

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken authenticationToken) {
        AuthenticationInfo authenticationInfo = null;
        if (authenticationToken instanceof OctopusSSOUser) {
            OctopusSSOUser octopusSSOUser = (OctopusSSOUser) authenticationToken;
            authenticationInfo = new SSOAuthenticationInfoBuilder(octopusSSOUser).getAuthenticationInfo();
        }
        return authenticationInfo;
    }
}
