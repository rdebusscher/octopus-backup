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
package be.c4j.ee.security.systemaccount;

import be.c4j.ee.security.realm.AuthenticationInfoBuilder;
import be.c4j.ee.security.realm.OctopusDefinedAuthenticationInfo;
import be.c4j.ee.security.realm.OctopusDefinedAuthorizationInfo;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class InfoForSystemAccount implements OctopusDefinedAuthenticationInfo, OctopusDefinedAuthorizationInfo {

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
        AuthenticationInfo authenticationInfo = null;

        if (token instanceof SystemAccountAuthenticationToken) {
            authenticationInfo = new SimpleAuthenticationInfo(token.getPrincipal(), "", AuthenticationInfoBuilder.DEFAULT_REALM);
        }
        return authenticationInfo;
    }

    @Override
    public AuthorizationInfo getAuthorizationInfo(Object primaryPrincipal) {
        if (primaryPrincipal instanceof SystemAccountPrincipal) {
            return new SimpleAuthorizationInfo();
        }
        return null;
    }
}
