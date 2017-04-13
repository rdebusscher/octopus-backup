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
import be.c4j.ee.security.permission.NamedDomainPermission;
import net.jadler.Jadler;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.jackson.JacksonFeature;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class PermissionRequestorTest {

    @Mock
    private OctopusSEConfiguration octopusSEConfigurationMock;

    private PermissionRequestor permissionRequestor;

    @Before
    public void setup() {
        ClientConfig clientConfiguration = new ClientConfig();
        clientConfiguration.register(JacksonFeature.class);

        permissionRequestor = new PermissionRequestor(octopusSEConfigurationMock, clientConfiguration);
        Jadler.initJadler();
    }

    @After
    public void tearDown() {
        Jadler.closeJadler();
    }

    @Test
    public void retrieveUserPermissions() {
        when(octopusSEConfigurationMock.getOctopusSSOServer()).thenReturn("http://localhost:" + Jadler.port() + "/oidc");
        when(octopusSEConfigurationMock.getSSOEndpointRoot()).thenReturn("data");
        when(octopusSEConfigurationMock.getSSOApplication()).thenReturn("junitApp");


        Jadler.onRequest()
                .havingPathEqualTo("/oidc/data/octopus/sso/user/permissions/junitApp")
                .havingHeader("Authorization")
                .respond()
                .withContentType("application/json")
                .withBody("{\"permission1\":\"permission:1:*\",\"permission2\":\"permission:2:*\"}");


        String accessToken = "TheAccessToken";
        List<NamedDomainPermission> permissions = permissionRequestor.retrieveUserPermissions(accessToken);
        assertThat(permissions).isNotEmpty();
        assertThat(permissions.get(0).getName()).isEqualTo("permission1");
        assertThat(permissions.get(0).getWildcardNotation()).isEqualTo("permission:1:*");

    }

    @Test
    public void retrieveAllPermissions() {
        when(octopusSEConfigurationMock.getOctopusSSOServer()).thenReturn("http://localhost:" + Jadler.port() + "/oidc");
        when(octopusSEConfigurationMock.getSSOEndpointRoot()).thenReturn("data");
        when(octopusSEConfigurationMock.getSSOApplication()).thenReturn("junitApp");


        Jadler.onRequest()
                .havingPathEqualTo("/oidc/data/octopus/sso/permissions/junitApp")
                .respond()
                .withContentType("application/json")
                .withBody("{\"permission1\":\"permission:1:*\",\"permission2\":\"permission:2:*\"}");

        List<NamedDomainPermission> permissions = permissionRequestor.retrieveAllPermissions();
        assertThat(permissions).isNotEmpty();
        assertThat(permissions.get(0).getName()).isEqualTo("permission1");
        assertThat(permissions.get(0).getWildcardNotation()).isEqualTo("permission:1:*");
    }

    @Test
    public void retrieveAllPermissions_Empty() {
        when(octopusSEConfigurationMock.getOctopusSSOServer()).thenReturn("http://localhost:" + Jadler.port() + "/oidc");
        when(octopusSEConfigurationMock.getSSOEndpointRoot()).thenReturn("data");
        when(octopusSEConfigurationMock.getSSOApplication()).thenReturn("junitApp");

        Jadler.onRequest()
                .havingPathEqualTo("/oidc/data/octopus/sso/permissions/junitApp")
                .respond()
                .withContentType("application/json")
                .withBody("{}");

        List<NamedDomainPermission> permissions = permissionRequestor.retrieveAllPermissions();
        assertThat(permissions).isEmpty();
    }

    @Test
    public void retrieveAllPermissions_Failure() {
        when(octopusSEConfigurationMock.getOctopusSSOServer()).thenReturn("http://localhost:" + Jadler.port() + "/oidc");
        when(octopusSEConfigurationMock.getSSOEndpointRoot()).thenReturn("data");
        when(octopusSEConfigurationMock.getSSOApplication()).thenReturn("junitApp");

        Jadler.onRequest()
                .havingPathEqualTo("/oidc/data/octopus/sso/permissions/junitApp")
                .respond()
                .withStatus(400)
                .withContentType("application/json")
                .withBody("Failure message");

        List<NamedDomainPermission> permissions = permissionRequestor.retrieveAllPermissions();
        assertThat(permissions).isEmpty();

        // TODO Catch logging

    }

}