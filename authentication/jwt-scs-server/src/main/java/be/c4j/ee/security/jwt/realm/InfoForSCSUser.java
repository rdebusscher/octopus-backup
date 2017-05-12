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
package be.c4j.ee.security.jwt.realm;

import be.c4j.ee.security.OctopusConstants;
import be.c4j.ee.security.jwt.SCSUser;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.realm.AuthenticationInfoBuilder;
import be.c4j.ee.security.realm.AuthorizationInfoBuilder;
import be.c4j.ee.security.realm.OctopusDefinedAuthenticationInfo;
import be.c4j.ee.security.realm.OctopusDefinedAuthorizationInfo;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class InfoForSCSUser implements OctopusDefinedAuthenticationInfo, OctopusDefinedAuthorizationInfo {

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken authenticationToken) {
        AuthenticationInfo authenticationInfo = null;
        if (authenticationToken instanceof SCSUser) {
            SCSUser SCSUser = (SCSUser) authenticationToken;
            AuthenticationInfoBuilder infoBuilder = new AuthenticationInfoBuilder();
            infoBuilder.name(SCSUser.getName());
            infoBuilder.userName(SCSUser.getUserName());
            infoBuilder.principalId(SCSUser.getId());
            infoBuilder.addUserInfo(OctopusConstants.EXTERNAL_ID, SCSUser.getExternalId());
            infoBuilder.addUserInfo(SCSUser.getUserInfo());
            authenticationInfo = infoBuilder.build();
        }
        return authenticationInfo;
    }

    @Override
    public AuthorizationInfo getAuthorizationInfo(Object primaryPrincipal) {

        if (primaryPrincipal instanceof UserPrincipal) {
            UserPrincipal user = (UserPrincipal) primaryPrincipal;
            Object token = user.getUserInfo("token");
            if (token instanceof SCSUser) {
                SCSUser SCSUser = (SCSUser) token;
                AuthorizationInfoBuilder authorizationInfoBuilder = new AuthorizationInfoBuilder();
                authorizationInfoBuilder.addRolesByName(SCSUser.getRoles());
                authorizationInfoBuilder.addStringPermissions(SCSUser.getPermissions());

                return authorizationInfoBuilder.build();
            }
        }
        return null;

    }
}
