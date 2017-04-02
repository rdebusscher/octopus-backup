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
package be.c4j.ee.security.sso.client;

import be.c4j.ee.security.authentication.octopus.OctopusSEConfiguration;
import be.c4j.ee.security.authentication.octopus.requestor.PermissionRequestor;
import be.c4j.ee.security.config.Debug;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.StringPermissionLookup;
import be.c4j.ee.security.realm.AuthorizationInfoBuilder;
import be.c4j.ee.security.realm.SecurityDataProvider;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import be.c4j.ee.security.sso.encryption.SSODataEncryptionHandler;
import be.c4j.ee.security.sso.realm.SSOAuthenticationInfoBuilder;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.servlet.ServletException;
import java.util.List;


@ApplicationScoped
public class SSOClientSecurityDataProvider implements SecurityDataProvider {

    @Inject
    private Logger logger;

    @Inject
    private OctopusSSOClientConfiguration config;

    @Inject
    private OctopusConfig octopusConfig;

    private SSODataEncryptionHandler encryptionHandler;

    private PermissionRequestor permissionRequestor;

    @PostConstruct
    public void init() throws ServletException {
        // FIXME Fix usage, is now broken
        encryptionHandler = BeanProvider.getContextualReference(SSODataEncryptionHandler.class, true);

        // FIXME, a way to specify the clientConfiguration as the second parameter
        permissionRequestor = new PermissionRequestor(new OctopusSEConfiguration(), null);

    }

    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {

        if (token instanceof OctopusSSOUser) {
            OctopusSSOUser user = (OctopusSSOUser) token;

            return new SSOAuthenticationInfoBuilder(user).getAuthenticationInfo();
        }

        return null;
    }

    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {

        principals.oneByType(OctopusSSOUser.class); // FIXME Check if we get the correct
        UserPrincipal userPrincipal = (UserPrincipal) principals.getPrimaryPrincipal();
        OctopusSSOUser ssoUser = userPrincipal.getUserInfo("token");

        String realToken = ssoUser.getAccessToken();

        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("Retrieving authorization info for user %s from Octopus SSO Server", ssoUser.getFullName()));
        }

        List<NamedDomainPermission> domainPermissions = permissionRequestor.retrieveUserPermissions(realToken);
        AuthorizationInfoBuilder infoBuilder = new AuthorizationInfoBuilder();
        infoBuilder.addPermissions(domainPermissions);

        return infoBuilder.build();
    }


    @ApplicationScoped
    @Produces
    public StringPermissionLookup createLookup() {

        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("Retrieving all permissions for application %s", config.getSSOApplication()));
        }

        List<NamedDomainPermission> permissions = permissionRequestor.retrieveAllPermissions();

        if (!permissions.isEmpty()) {
            return new StringPermissionLookup(permissions);
        }
        return null;

    }


}
