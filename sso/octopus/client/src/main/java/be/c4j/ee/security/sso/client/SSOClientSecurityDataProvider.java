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
package be.c4j.ee.security.sso.client;

import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.StringPermissionLookup;
import be.c4j.ee.security.realm.AuthenticationInfoBuilder;
import be.c4j.ee.security.realm.AuthorizationInfoBuilder;
import be.c4j.ee.security.realm.SecurityDataProvider;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import be.c4j.ee.security.sso.encryption.SSODataEncryptionHandler;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;

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

import static be.c4j.ee.security.sso.OctopusSSOUser.USER_INFO_KEY;

@ApplicationScoped
public class SSOClientSecurityDataProvider implements SecurityDataProvider {

    private static final String OCTOPUS_SSO_TOKEN = "Octopus-SSO-Token";
    @Inject
    private SSODataEncryptionHandler encryptionHandler;

    @Inject
    private OctopusSSOClientConfiguration config;

    private Client client;

    @PostConstruct
    public void init() throws ServletException {

        client = ClientBuilder.newClient();
    }

    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {

        if (token instanceof OctopusSSOUser) {
            OctopusSSOUser user = (OctopusSSOUser) token;

            AuthenticationInfoBuilder authenticationInfoBuilder = new AuthenticationInfoBuilder();

            authenticationInfoBuilder
                    .principalId(user.getLocalId())
                    .userName(user.getUserName())
                    .name(user.getFullName())
                    .addUserInfo(OCTOPUS_SSO_TOKEN, user.getToken())
                    .addUserInfo(USER_INFO_KEY, user)
                    .addUserInfo("mail", user.getEmail());

            return authenticationInfoBuilder.build();
        }

        return null;
    }

    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {

        UserPrincipal userPrincipal = (UserPrincipal) principals.getPrimaryPrincipal();
        String realToken = userPrincipal.getUserInfo(OCTOPUS_SSO_TOKEN);

        WebTarget target = client.target(config.getSSOServer() + "/" + config.getSSOEndpointRoot() + "/octopus/sso/user/permissions/" + config.getSSOApplication());

        Response response = target.request()
                .header("Authorization", "Bearer " + defineToken(realToken))
                .accept(MediaType.APPLICATION_JSON)
                .get();

        Map<String, String> data = response.readEntity(Map.class);

        List<NamedDomainPermission> permissions = toNamedDomainPermissions(data);

        AuthorizationInfoBuilder infoBuilder = new AuthorizationInfoBuilder();
        infoBuilder.addPermissions(permissions);

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

        WebTarget target = client.target(config.getSSOServer() + "/" + config.getSSOEndpointRoot() + "/octopus/sso/permissions/" + config.getSSOApplication());

        Response response = target.request()
                .accept(MediaType.APPLICATION_JSON)
                .get();

        Map<String, String> data = response.readEntity(Map.class);

        List<NamedDomainPermission> permissions = toNamedDomainPermissions(data);

        return new StringPermissionLookup(permissions);

    }

    private List<NamedDomainPermission> toNamedDomainPermissions(Map<String, String> data) {
        List<NamedDomainPermission> permissions = new ArrayList<NamedDomainPermission>();
        for (Map.Entry<String, String> entry : data.entrySet()) {
            permissions.add(new NamedDomainPermission(entry.getKey(), entry.getValue()));
        }
        return permissions;
    }

}
