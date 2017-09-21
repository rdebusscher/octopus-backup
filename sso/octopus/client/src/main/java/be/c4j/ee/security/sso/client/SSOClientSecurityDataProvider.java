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
import be.c4j.ee.security.authentication.octopus.client.ClientCustomization;
import be.c4j.ee.security.authentication.octopus.requestor.PermissionRequestor;
import be.c4j.ee.security.config.Debug;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.PermissionJSONProvider;
import be.c4j.ee.security.permission.StringPermissionLookup;
import be.c4j.ee.security.realm.AuthorizationInfoBuilder;
import be.c4j.ee.security.realm.SecurityDataProvider;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import be.c4j.ee.security.sso.client.fake.FakePermissionProvider;
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
import java.util.List;

import static be.c4j.ee.security.OctopusConstants.TOKEN;


@ApplicationScoped
public class SSOClientSecurityDataProvider implements SecurityDataProvider {

    @Inject
    private Logger logger;

    @Inject
    private OctopusSSOClientConfiguration config;

    @Inject
    private OctopusConfig octopusConfig;

    private PermissionRequestor permissionRequestor;

    @PostConstruct
    public void init() {
        // The PermissionJSONProvider is located in a JAR With CDI support.
        // Developer must have to opportunity to define a custom version.
        // So first look at CDI class. If not found, use the default.
        PermissionJSONProvider permissionJSONProvider = BeanProvider.getContextualReference(PermissionJSONProvider.class, true);
        if (permissionJSONProvider == null) {
            permissionJSONProvider = new PermissionJSONProvider();
        }

        ClientCustomization clientCustomization = BeanProvider.getContextualReference(ClientCustomization.class, true);
        if (clientCustomization == null) {
            permissionRequestor = new PermissionRequestor(new OctopusSEConfiguration(), null, null, permissionJSONProvider);
        } else {
            permissionRequestor = new PermissionRequestor(new OctopusSEConfiguration(), clientCustomization, clientCustomization.getConfiguration(PermissionRequestor.class), permissionJSONProvider);
        }

    }

    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {

        if (token instanceof OctopusSSOUser) {
            OctopusSSOUser user = (OctopusSSOUser) token;

            return new SSOAuthenticationInfoBuilder(user).getAuthenticationInfo();
        }

        return null;
    }

    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {

        UserPrincipal userPrincipal = (UserPrincipal) principals.getPrimaryPrincipal();

        Object token = userPrincipal.getUserInfo(TOKEN);
        AuthorizationInfoBuilder infoBuilder = new AuthorizationInfoBuilder();

        if (!(token instanceof OctopusSSOUser)) {
            throw new OctopusUnexpectedException("UserPrincipal should be based OctopusSSOUser. Dit you you fakeLogin Module and forget to define Permissions for the fake user?");
        }
        OctopusSSOUser ssoUser = (OctopusSSOUser) token;

        String realToken = ssoUser.getAccessToken();

        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("(SSO Client) Retrieving authorization info for user %s from Octopus SSO Server", ssoUser.getFullName()));
        }

        List<NamedDomainPermission> domainPermissions = permissionRequestor.retrieveUserPermissions(realToken);
        infoBuilder.addPermissions(domainPermissions);

        return infoBuilder.build();
    }


    @ApplicationScoped
    @Produces
    public StringPermissionLookup createLookup() {

        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("(SSO Client) Retrieving all permissions for application %s", config.getSSOApplication()));
        }

        List<NamedDomainPermission> permissions = permissionRequestor.retrieveAllPermissions();

        if (!permissions.isEmpty()) {
            return new StringPermissionLookup(permissions);
        }

        if (isFakeLoginActive()) {

            FakePermissionProvider fakePermissionProvider = BeanProvider.getContextualReference(FakePermissionProvider.class, true);
            if (fakePermissionProvider != null) {
                return new StringPermissionLookup(fakePermissionProvider.getApplicationPermissions());
            }
        }
        throw new OctopusConfigurationException("Unable to create StringPermissionLookup, See ??? for solutions");

    }

    private boolean isFakeLoginActive() {
        boolean result = false;
        try {
            Class.forName("be.c4j.ee.security.credentials.authentication.fake.FakeAuthenticationServlet");
            result = true;
        } catch (ClassNotFoundException e) {
            ; // Nothing to do, fakeLogin Module isn't with classpath.
        }
        return result;
    }


}
