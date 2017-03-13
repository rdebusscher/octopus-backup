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
import be.c4j.test.TestConfigSource;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.junit.After;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class OctopusSSOClientConfigurationTest {

    private OctopusSSOClientConfiguration configuration = new OctopusSSOClientConfiguration();

    @After
    public void teardown() {
        ConfigResolver.freeConfigSources();
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getSSOType_unknown() {
        TestConfigSource.defineConfigValue("token");
        configuration.getSSOType();
    }

    @Test
    public void getSSOType_singleApp() {
        TestConfigSource.defineConfigValue("id-token");
        assertThat(configuration.getSSOType()).isEqualTo(SSOFlow.IMPLICIT);
    }

    @Test
    public void getSSOType_multiApp() {
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("SSO.application", "app2");
        parameters.put("app1.SSO.flow", "id-token");
        parameters.put("app2.SSO.flow", "code");
        TestConfigSource.defineConfigValue(parameters);

        assertThat(configuration.getSSOType()).isEqualTo(SSOFlow.AUTHORIZATION_CODE);
    }

    @Test
    public void getSSOScopes() {
        assertThat(configuration.getSSOScopes()).isEqualTo("");
    }

}