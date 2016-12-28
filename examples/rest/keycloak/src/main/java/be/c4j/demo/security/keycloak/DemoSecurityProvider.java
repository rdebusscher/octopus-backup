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

import be.c4j.ee.security.credentials.authentication.keycloak.KeycloakUser;
import be.c4j.ee.security.realm.AuthenticationInfoBuilder;
import be.c4j.ee.security.realm.SecurityDataProvider;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class DemoSecurityProvider implements SecurityDataProvider {
    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {

        if (token instanceof KeycloakUser) {
            KeycloakUser user = (KeycloakUser) token;

            AuthenticationInfoBuilder authenticationInfoBuilder = new AuthenticationInfoBuilder();
            authenticationInfoBuilder.principalId(user.getId()).name(user.getFullName());
            authenticationInfoBuilder.addUserInfo(user.getUserInfo());

            return authenticationInfoBuilder.build();
        }

        return null;

    }

    @Override
    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {
        return new SimpleAuthorizationInfo();
    }
}
