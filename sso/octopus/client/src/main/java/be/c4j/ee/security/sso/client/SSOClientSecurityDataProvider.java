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

import be.c4j.ee.security.config.Debug;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.StringPermissionLookup;
import be.c4j.ee.security.realm.AuthorizationInfoBuilder;
import be.c4j.ee.security.realm.SecurityDataProvider;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import be.c4j.ee.security.sso.client.debug.DebugClientResponseFilter;
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
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


@ApplicationScoped
public class SSOClientSecurityDataProvider implements SecurityDataProvider {

    @Inject
    private Logger logger;

    @Inject
    private OctopusSSOClientConfiguration config;

    @Inject
    private OctopusConfig octopusConfig;

    private SSODataEncryptionHandler encryptionHandler;

    private Client client;

    @PostConstruct
    public void init() throws ServletException {

        client = ClientBuilder.newClient();
        encryptionHandler = BeanProvider.getContextualReference(SSODataEncryptionHandler.class, true);

        if (octopusConfig.showDebugFor().contains(Debug.SSO_REST)) {
            client.register(DebugClientResponseFilter.class);
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
        OctopusSSOUser ssoUser = userPrincipal.getUserInfo("token");
        String realToken = ssoUser.getAccessToken();

        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("Retrieving authorization info for user %s from Octopus SSO Server", ssoUser.getFullName()));
        }

        WebTarget target = client.target(config.getSSOServer() + "/" + config.getSSOEndpointRoot() + "/octopus/sso/user/permissions/" + config.getSSOApplication());

        Response response = target.request()
                .header("Authorization", "Bearer " + defineToken(realToken))
                .accept(MediaType.APPLICATION_JSON)
                .get();

        AuthorizationInfoBuilder infoBuilder = new AuthorizationInfoBuilder();

        if (response.getStatus() == 200) {
            Map<String, String> data = response.readEntity(Map.class);

            List<NamedDomainPermission> permissions = toNamedDomainPermissions(data);

            infoBuilder.addPermissions(permissions);
        }

        response.close();

        return infoBuilder.build();
    }

    private String defineToken(String token) {
        String result;
        if (encryptionHandler != null) {
            result = encryptionHandler.encryptData(token, null);
        } else {
            result = token;
        }
        return result;
    }

    @ApplicationScoped
    @Produces
    public StringPermissionLookup createLookup() {

        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("Retrieving all permissions for application %s", config.getSSOApplication()));
        }

        WebTarget target = client.target(config.getSSOServer() + "/" + config.getSSOEndpointRoot() + "/octopus/sso/permissions/" + config.getSSOApplication());

        Response response = target.request()
                .accept(MediaType.APPLICATION_JSON)
                .get();

        if (response.getStatus() == 200) {
            Map<String, String> data = response.readEntity(Map.class);

            List<NamedDomainPermission> permissions = toNamedDomainPermissions(data);
            return new StringPermissionLookup(permissions);
        } else {
            String message = response.readEntity(String.class);
            System.out.println(message); // FIXME
        }
        return null;

    }

    private List<NamedDomainPermission> toNamedDomainPermissions(Map<String, String> data) {
        List<NamedDomainPermission> permissions = new ArrayList<NamedDomainPermission>();
        for (Map.Entry<String, String> entry : data.entrySet()) {
            permissions.add(new NamedDomainPermission(entry.getKey(), entry.getValue()));
        }
        return permissions;
    }

}
