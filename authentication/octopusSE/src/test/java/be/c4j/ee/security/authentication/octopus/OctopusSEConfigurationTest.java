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
package be.c4j.ee.security.authentication.octopus;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.util.SecretUtil;
import be.c4j.test.TestConfigSource;
import com.nimbusds.jose.util.Base64;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class OctopusSEConfigurationTest {
    private OctopusSEConfiguration configuration = new OctopusSEConfiguration();

    private SecretUtil secretUtil;

    @Before
    public void setup() {
        secretUtil = new SecretUtil();
        secretUtil.init();
    }

    @After
    public void teardown() {
        ConfigResolver.freeConfigSources();
    }

    @Test
    public void getSSOClientSecret() {
        String secret = secretUtil.generateSecretBase64(32);
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("SSO.clientSecret", secret);
        TestConfigSource.defineConfigValue(parameters);

        assertThat(configuration.getSSOClientSecret()).isEqualTo(new Base64(secret).decode());
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getSSOClientSecret_TooShort() {
        String secret = secretUtil.generateSecretBase64(28);
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("SSO.clientSecret", secret);
        TestConfigSource.defineConfigValue(parameters);

        byte[] data = configuration.getSSOClientSecret();
        assertThat(data).hasSize(0);
    }

    @Test
    public void getSSOClientSecret_NotRequired() {
        Map<String, String> parameters = new HashMap<String, String>();
        TestConfigSource.defineConfigValue(parameters);

        assertThat(configuration.getSSOClientSecret()).isEmpty();
    }

    @Test
    public void getSSOClientSecret_multiApp() {
        String secret = secretUtil.generateSecretBase64(32);
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("SSO.application", "app2");
        parameters.put("app2.SSO.clientSecret", secret);
        TestConfigSource.defineConfigValue(parameters);

        assertThat(configuration.getSSOClientSecret()).isEqualTo(new Base64(secret).decode());
    }

    @Test
    public void getSSOClientId() {
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("SSO.clientId", "ClientId");
        TestConfigSource.defineConfigValue(parameters);

        String clientId = configuration.getSSOClientId();
        assertThat(clientId).isEqualTo("ClientId");
    }

    @Test
    public void getSSOClientId_multiApp() {
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("SSO.application", "app2");
        parameters.put("app1.SSO.clientId", "ClientId");
        parameters.put("app2.SSO.clientId", "OtherId");
        TestConfigSource.defineConfigValue(parameters);

        String clientId = configuration.getSSOClientId();
        assertThat(clientId).isEqualTo("OtherId");
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getSSOClientId_required() {

        configuration.getSSOClientId();

    }

    @Test
    public void getSSOEndpointRoot() {
        TestConfigSource.defineConfigValue("junit");
        String endpointRoot = configuration.getSSOEndpointRoot();
        assertThat(endpointRoot).isEqualTo("junit");
    }

    @Test
    public void getSSOEndpointRoot_trimmed() {
        TestConfigSource.defineConfigValue("/trimmed/only/begin/and/end//");
        String endpointRoot = configuration.getSSOEndpointRoot();
        assertThat(endpointRoot).isEqualTo("trimmed/only/begin/and/end");
    }
}