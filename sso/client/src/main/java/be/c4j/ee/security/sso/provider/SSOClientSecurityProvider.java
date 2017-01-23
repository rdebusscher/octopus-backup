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
 *
 */
package be.c4j.ee.security.sso.provider;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.realm.AuthenticationInfoBuilder;
import be.c4j.ee.security.realm.AuthorizationInfoBuilder;
import be.c4j.ee.security.realm.SecurityDataProvider;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.io.Serializable;
import java.util.List;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class SSOClientSecurityProvider implements SecurityDataProvider {

    @Inject
    private PermissionProvider permissionProvider;

    @Inject
    private AuthenticationInfoProvider authenticationInfoProvider;

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
        if (token instanceof OAuth2User) {
            OAuth2User googleUser = (OAuth2User) token;
            AuthenticationInfoBuilder authenticationInfoBuilder = new AuthenticationInfoBuilder();
            authenticationInfoBuilder.principalId(googleUser.getId()).name(googleUser.getFullName());
            Map<Serializable, Serializable> userInfo = googleUser.getUserInfo();

            authenticationInfoBuilder.addUserInfo(userInfo);

            authenticationInfoBuilder.addUserInfo(OAuth2User.LOCAL_ID, googleUser.getLocalId());

            authenticationInfoBuilder.addUserInfo(authenticationInfoProvider.additionalUserInfo(userInfo));

            return authenticationInfoBuilder.build();

        }
        return null;

    }

    @Override
    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {
        AuthorizationInfoBuilder authorizationInfoBuilder = new AuthorizationInfoBuilder();
        UserPrincipal primaryPrincipal = (UserPrincipal) principals.getPrimaryPrincipal();
        Serializable localId = primaryPrincipal.getInfo().get(OAuth2User.LOCAL_ID);

        List<NamedPermission> permissions = permissionProvider.getNamedPermissions(localId);

        for (NamedPermission permission : permissions) {
            authorizationInfoBuilder.addPermission(permission);
        }

        return authorizationInfoBuilder.build();

    }
}
