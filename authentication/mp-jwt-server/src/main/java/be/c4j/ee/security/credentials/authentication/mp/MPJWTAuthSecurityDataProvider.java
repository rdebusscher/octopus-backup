/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.c4j.ee.security.credentials.authentication.mp;

import be.c4j.ee.security.OctopusConstants;
import be.c4j.ee.security.credentials.authentication.mp.token.MPJWTToken;
import be.c4j.ee.security.credentials.authentication.mp.token.MPToken;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.realm.AuthorizationInfoBuilder;
import be.c4j.ee.security.realm.SecurityDataProvider;
import be.c4j.ee.security.role.SimpleNamedRole;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;

import javax.enterprise.context.ApplicationScoped;

import static be.c4j.ee.security.realm.AuthenticationInfoBuilder.DEFAULT_REALM;

/**
 * SecurityDataProvider for MicroProfile JWT Auth token.
 */
@ApplicationScoped
public class MPJWTAuthSecurityDataProvider implements SecurityDataProvider {

    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {

        if (token instanceof MPToken) {
            MPToken mpToken = (MPToken) token;
            MPJWTToken mpjwtToken = (MPJWTToken) mpToken.getCredentials();

            UserPrincipal principal = new UserPrincipal(mpToken.getId(), mpjwtToken.getPreferredUsername(), mpjwtToken.getAdditionalClaim("name"));

            principal.addUserInfo(mpjwtToken.getAdditionalClaims());
            return new SimpleAuthenticationInfo(principal, null, DEFAULT_REALM);
        }

        return null;
    }

    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {

        UserPrincipal userPrincipal = (UserPrincipal) principals.getPrimaryPrincipal();
        MPToken mpToken = userPrincipal.getUserInfo(OctopusConstants.TOKEN);

        MPJWTToken mpjwtToken = (MPJWTToken) mpToken.getCredentials();

        AuthorizationInfoBuilder infoBuilder = new AuthorizationInfoBuilder();
        for (String group : mpjwtToken.getGroups()) {
            if (!group.contains(":")) {
                //No : within name, so it can be a real role.
                infoBuilder.addRole(new SimpleNamedRole(group));
            }
            // Always treat the name as permission (simple string name or name has : and thus probably wildCardPermission
            infoBuilder.addPermission(new NamedDomainPermission(group, group)); // TODO Do we need to generate some proper name for the wildcardPermission?
        }
        return infoBuilder.build();
    }

}
