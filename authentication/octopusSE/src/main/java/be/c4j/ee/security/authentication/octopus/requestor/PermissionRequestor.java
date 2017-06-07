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
package be.c4j.ee.security.authentication.octopus.requestor;

import be.c4j.ee.security.authentication.octopus.OctopusSEConfiguration;
import be.c4j.ee.security.authentication.octopus.client.ClientCustomization;
import be.c4j.ee.security.authentication.octopus.debug.DebugClientRequestFilter;
import be.c4j.ee.security.authentication.octopus.debug.DebugClientResponseFilter;
import be.c4j.ee.security.config.Debug;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.PermissionJSONProvider;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Configuration;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static be.c4j.ee.security.OctopusConstants.AUTHORIZATION_HEADER;
import static be.c4j.ee.security.OctopusConstants.BEARER;

/**
 *
 */

public class PermissionRequestor extends AbstractRequestor {

    private Client client;

    private PermissionJSONProvider permissionJSONProvider;

    public PermissionRequestor(OctopusSEConfiguration configuration, ClientCustomization clientCustomization, Configuration clientConfiguration, PermissionJSONProvider permissionJSONProvider) {
        super(configuration);
        this.permissionJSONProvider = permissionJSONProvider;
        init(clientConfiguration, clientCustomization);
    }

    private void init(Configuration clientConfiguration, ClientCustomization clientCustomization) {
        if (clientConfiguration != null) {
            client = ClientBuilder.newClient(clientConfiguration);
        } else {
            client = ClientBuilder.newClient();
        }

        if (configuration.showDebugFor().contains(Debug.SSO_REST)) {
            client.register(DebugClientResponseFilter.class);
            client.register(DebugClientRequestFilter.class);
        }

        if (clientCustomization != null) {
            clientCustomization.customize(client, this.getClass());
        }

    }

    public List<NamedDomainPermission> retrieveUserPermissions(String accessToken) {
        List<NamedDomainPermission> permissions;
        WebTarget target = client.target(configuration.getOctopusSSOServer() + "/" + configuration.getSSOEndpointRoot() + "/octopus/sso/user/permissions/" + configuration.getSSOApplication());

        Response response = target.request()
                .header(AUTHORIZATION_HEADER, BEARER + " " + defineToken(accessToken))
                .accept(MediaType.APPLICATION_JSON)
                .get();

        permissions = getNamedDomainPermissions(response);

        response.close();
        return permissions;
    }

    private List<NamedDomainPermission> getNamedDomainPermissions(Response response) {
        List<NamedDomainPermission> permissions = null;
        if (response.getStatus() == 200) {
            Map<String, String> data = response.readEntity(Map.class);

            permissions = toNamedDomainPermissions(data);
        }
        if (response.getStatus() == 204) {
            permissions = new ArrayList<NamedDomainPermission>();
            // empty result, so no permissions assigned or not the correct scope specified.
        }
        if (permissions == null) {

            String message = response.readEntity(String.class);
            logger.warn(String.format("Retrieving all permissions for application %s failed with %s", configuration.getSSOApplication(), message));

            permissions = new ArrayList<NamedDomainPermission>();

        }
        return permissions;
    }

    private String defineToken(String token) {
        String result;
        /*
        FIXME
        if (encryptionHandler != null) {
            result = encryptionHandler.encryptData(token, null);
        } else {
        */
        result = token;
        //}
        return result;
    }


    private List<NamedDomainPermission> toNamedDomainPermissions(Map<String, String> data) {
        List<NamedDomainPermission> permissions = new ArrayList<NamedDomainPermission>();
        for (Map.Entry<String, String> entry : data.entrySet()) {
            permissions.add(permissionJSONProvider.readValue(entry.getKey(), entry.getValue()));
        }
        return permissions;
    }

    public List<NamedDomainPermission> retrieveAllPermissions() {
        List<NamedDomainPermission> permissions;
        WebTarget target = client.target(configuration.getOctopusSSOServer() + "/" + configuration.getSSOEndpointRoot() + "/octopus/sso/permissions/" + configuration.getSSOApplication());

        Response response = target.request()
                .accept(MediaType.APPLICATION_JSON)
                .get();

        permissions = getNamedDomainPermissions(response);
        return permissions;
    }

}
