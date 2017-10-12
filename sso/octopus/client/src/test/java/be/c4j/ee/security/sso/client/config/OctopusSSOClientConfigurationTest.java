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
package be.c4j.ee.security.sso.client.config;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.sso.SSOFlow;
import be.c4j.ee.security.util.SecretUtil;
import be.c4j.ee.security.util.StringUtil;
import be.c4j.test.TestConfigSource;
import be.c4j.test.util.ReflectionUtil;
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
public class OctopusSSOClientConfigurationTest {

    private OctopusSSOClientConfiguration configuration = new OctopusSSOClientConfiguration();

    private SecretUtil secretUtil;

    @Before
    public void setup() throws IllegalAccessException {
        secretUtil = new SecretUtil();
        secretUtil.init();

        ReflectionUtil.injectDependencies(configuration, new StringUtil());
    }

    @After
    public void teardown() {
        ConfigResolver.freeConfigSources();
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getSSOType_unknown() {
        TestConfigSource.defineConfigValue("id_token");
        configuration.getSSOType();
    }

    @Test
    public void getSSOType_singleApp() {
        TestConfigSource.defineConfigValue("token");
        assertThat(configuration.getSSOType()).isEqualTo(SSOFlow.IMPLICIT);
    }

    @Test
    public void getSSOType_multiApp() {
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("SSO.application", "app2");
        parameters.put("app1.SSO.flow", "token");
        parameters.put("app2.SSO.flow", "code");
        TestConfigSource.defineConfigValue(parameters);

        assertThat(configuration.getSSOType()).isEqualTo(SSOFlow.AUTHORIZATION_CODE);
    }

    @Test
    public void getSSOScopes() {
        assertThat(configuration.getSSOScopes()).isEqualTo("");
    }


    @Test
    public void getSSOClientSecret() {
        String secret = secretUtil.generateSecretBase64(32);
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("SSO.flow", "code");
        parameters.put("SSO.clientSecret", secret);
        TestConfigSource.defineConfigValue(parameters);

        assertThat(configuration.getSSOClientSecret()).isEqualTo(new Base64(secret).decode());
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getSSOClientSecret_Missing() {
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("SSO.flow", "code");
        TestConfigSource.defineConfigValue(parameters);

        configuration.getSSOClientSecret();
    }

    @Test
    public void getSSOClientSecret_NotRequired() {
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("SSO.flow", "token");
        TestConfigSource.defineConfigValue(parameters);

        assertThat(configuration.getSSOClientSecret()).isEmpty();
    }

    @Test
    public void getSSOClientSecret_multiApp() {
        String secret = secretUtil.generateSecretBase64(32);
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("SSO.application", "app2");
        parameters.put("app1.SSO.flow", "token");
        parameters.put("app2.SSO.flow", "code");
        parameters.put("app2.SSO.clientSecret", secret);
        TestConfigSource.defineConfigValue(parameters);

        assertThat(configuration.getSSOClientSecret()).isEqualTo(new Base64(secret).decode());
    }

    @Test
    public void getSSOIdTokenSecret() {
        String secret = secretUtil.generateSecretBase64(32);
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("SSO.idTokenSecret", secret);
        TestConfigSource.defineConfigValue(parameters);

        assertThat(configuration.getSSOIdTokenSecret()).isEqualTo(new Base64(secret).decode());
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getSSOIdTokenSecret_Missing() {
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("SSO.flow", "code");
        TestConfigSource.defineConfigValue(parameters);

        configuration.getSSOIdTokenSecret();
    }

    @Test
    public void getSSOIdTokenSecret_multiApp() {
        String secret = secretUtil.generateSecretBase64(32);
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("SSO.application", "app2");
        parameters.put("app2.SSO.idTokenSecret", secret);
        TestConfigSource.defineConfigValue(parameters);

        assertThat(configuration.getSSOIdTokenSecret()).isEqualTo(new Base64(secret).decode());
    }


}