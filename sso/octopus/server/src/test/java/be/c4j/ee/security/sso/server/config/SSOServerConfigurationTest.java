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
package be.c4j.ee.security.sso.server.config;

import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.apache.deltaspike.core.spi.config.ConfigSource;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Describe in this block the functionality of the class.
 * Created by rubus on 13/02/17.
 */
@RunWith(MockitoJUnitRunner.class)
public class SSOServerConfigurationTest {

    private SSOServerConfiguration configuration = new SSOServerConfiguration();

    @After
    public void teardown() {
        ConfigResolver.freeConfigSources();
    }

    @Test
    public void getSSOCookieTimeToLive_hours() {
        defineConfigValue("8h");

        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(8);
    }

    @Test
    public void getSSOCookieTimeToLive_days() {
        defineConfigValue("12d");

        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(12 * 24);
    }

    @Test
    public void getSSOCookieTimeToLive_months() {
        defineConfigValue("1m");

        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(24 * 30);
    }

    private void defineConfigValue(String configValue) {

        List<ConfigSource> configSources = new ArrayList<ConfigSource>();
        configSources.add(new TestConfigSource(configValue));
        ConfigResolver.addConfigSources(configSources);
    }

    @Test
    public void getSSOCookieTimeToLive_default() {

        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(10);
    }

    @Test
    public void getSSOCookieTimeToLive_wrongValue() {
        defineConfigValue("JUnit");
        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(10); // Default Value
    }

    @Test
    public void getSSOCookieTimeToLive_Zero() {
        defineConfigValue("0h");
        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(10); // Default Value
    }

    @Test
    public void getSSOCookieTimeToLive_negative() {
        defineConfigValue("-1D");
        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(10); // Default Value
    }

    private class TestConfigSource implements ConfigSource {

        private String configValue;

        private TestConfigSource(String configValue) {
            this.configValue = configValue;
        }

        @Override
        public int getOrdinal() {
            return 0;
        }

        @Override
        public Map<String, String> getProperties() {
            return null;
        }

        @Override
        public String getPropertyValue(String key) {
            return configValue;
        }

        @Override
        public String getConfigName() {
            return null;
        }

        @Override
        public boolean isScannable() {
            return false;
        }
    }
}