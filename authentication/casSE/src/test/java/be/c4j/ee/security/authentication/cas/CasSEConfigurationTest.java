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
package be.c4j.ee.security.authentication.cas;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.test.TestConfigSource;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class CasSEConfigurationTest {

    private CasSEConfiguration configuration;

    @Before
    public void setup() {
        configuration = new CasSEConfiguration();
        CasSEConfiguration.prepareConfiguration();
    }

    @After
    public void teardown() {
        ConfigResolver.freeConfigSources();
    }

    @Test
    public void getCASProtocol_default() {
        CASProtocol result = configuration.getCASProtocol();
        assertThat(result).isEqualTo(CASProtocol.CAS);
    }

    @Test
    public void getCASProtocol_SAML() {
        TestConfigSource.defineConfigValue("saml");

        CASProtocol result = configuration.getCASProtocol();
        assertThat(result).isEqualTo(CASProtocol.SAML);
    }

    @Test
    public void getCASProtocol_cas() {
        TestConfigSource.defineConfigValue("cas");

        CASProtocol result = configuration.getCASProtocol();
        assertThat(result).isEqualTo(CASProtocol.CAS);
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getCASProtocol_Unknown() {
        TestConfigSource.defineConfigValue("JUnit");

        configuration.getCASProtocol();
    }

}