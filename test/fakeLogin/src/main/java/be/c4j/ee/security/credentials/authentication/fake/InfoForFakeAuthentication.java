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
package be.c4j.ee.security.credentials.authentication.fake;

import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.realm.OctopusDefinedAuthenticationInfo;
import be.c4j.ee.security.realm.OctopusDefinedAuthorizationInfo;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;

import javax.enterprise.context.ApplicationScoped;

import static be.c4j.ee.security.OctopusConstants.TOKEN;

/**
 *
 */
@ApplicationScoped
public class InfoForFakeAuthentication implements OctopusDefinedAuthenticationInfo, OctopusDefinedAuthorizationInfo {


    @Override
    public AuthorizationInfo getAuthorizationInfo(Object primaryPrincipal) {
        if (primaryPrincipal instanceof UserPrincipal) {
            UserPrincipal userPrincipal = (UserPrincipal) primaryPrincipal;
            Object token = userPrincipal.getUserInfo(TOKEN);
            if (token instanceof FakeAuthenticationToken) {
                FakeAuthenticationToken fakeToken = (FakeAuthenticationToken) token;
                FakePrincipal fakePrincipal = (FakePrincipal) fakeToken.getPrincipal();
                return fakePrincipal.getAuthorizationInfo();
            }
        }
        return null;
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
        if (token instanceof FakeAuthenticationToken) {
            FakeAuthenticationToken fakeToken = (FakeAuthenticationToken) token;
            FakePrincipal fakePrincipal = (FakePrincipal) fakeToken.getPrincipal();
            return fakePrincipal.getAuthenticationInfo();
        }
        return null;
    }
}
