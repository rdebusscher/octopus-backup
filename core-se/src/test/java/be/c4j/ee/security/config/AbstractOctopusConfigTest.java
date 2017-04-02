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
package be.c4j.ee.security.config;

import be.c4j.test.util.ReflectionUtil;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.apache.deltaspike.core.spi.config.ConfigSource;
import org.junit.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class AbstractOctopusConfigTest {
    @Test
    public void defineConfigurationSources() throws NoSuchFieldException, IllegalAccessException {
        String configFile = this.getClass().getResource("/testConfig.properties").toExternalForm();
        System.setProperty("octopus.cfg", configFile);

        TestOctopusConfig config = new TestOctopusConfig();

        config.defineConfigurationSources();

        Map<Object, Object> configSources = ReflectionUtil.getStaticFieldValue(ConfigResolver.class, "configSources");
        // Map is Classloader based
        ConfigSource[] sources = (ConfigSource[]) configSources.entrySet().iterator().next().getValue();

        assertThat(sources).hasSize(5); // 3 Default + 2 Added

        assertThat(sources[3].getConfigName()).isEqualTo("Octopus-configuration");
        assertThat(sources[4].getConfigName()).isEqualTo("octopusConfig.properties");

        String value = ConfigResolver.getPropertyValue("key");
        assertThat(value).isEqualTo("value");

        // default = octopusConfig.properties -> valueOverriden
        // With System property = testConfig.properties -> value

        // Value from system property config file must override the other defined ones.


    }

    private static class TestOctopusConfig extends AbstractOctopusConfig {

    }
}