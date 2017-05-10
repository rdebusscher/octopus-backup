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
package be.c4j.ee.security.credentials.authentication.jwt.client.config;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.jwt.config.JWTUserConfig;
import be.c4j.test.TestConfigSource;
import be.c4j.test.util.ReflectionUtil;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class JWTClientConfigTest {

    private JWTClientConfig jwtClientConfig;

    @Before
    public void setup() throws IllegalAccessException {
        jwtClientConfig = new JWTClientConfig();
        ReflectionUtil.injectDependencies(jwtClientConfig, new JWTUserConfig());
    }

    @After
    public void teardown() {
        ConfigResolver.freeConfigSources();
    }

    @Test
    public void getJWTTimeToLive() {
        TestConfigSource.defineConfigValue("5");

        int timeToLive = jwtClientConfig.getJWTTimeToLive();
        assertThat(timeToLive).isEqualTo(5);
    }

    @Test
    public void getJWTTimeToLive_defaultValue() {

        int timeToLive = jwtClientConfig.getJWTTimeToLive();
        assertThat(timeToLive).isEqualTo(2);
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getJWTTimeToLive_invalidValue() {
        TestConfigSource.defineConfigValue("JUnit");

        jwtClientConfig.getJWTTimeToLive();
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getJWTTimeToLive_negativeValue() {
        TestConfigSource.defineConfigValue("-1");

        jwtClientConfig.getJWTTimeToLive();
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getJWTTimeToLive_zeroValue() {
        TestConfigSource.defineConfigValue("0");

        jwtClientConfig.getJWTTimeToLive();
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getJwtSignature() {
        // On the JWT User Client side, the JWT Signature is required!!

        jwtClientConfig.getJwtSignature();

    }


}