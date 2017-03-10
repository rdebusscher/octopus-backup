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

import be.c4j.test.TestConfigSource;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
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
        TestConfigSource.defineConfigValue("8h");

        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(8);
    }

    @Test
    public void getSSOCookieTimeToLive_days() {
        TestConfigSource.defineConfigValue("12d");

        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(12 * 24);
    }

    @Test
    public void getSSOCookieTimeToLive_months() {
        TestConfigSource.defineConfigValue("1m");

        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(24 * 30);
    }

    @Test
    public void getSSOCookieTimeToLive_default() {

        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(10);
    }

    @Test
    public void getSSOCookieTimeToLive_wrongValue() {
        TestConfigSource.defineConfigValue("JUnit");
        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(10); // Default Value
    }

    @Test
    public void getSSOCookieTimeToLive_Zero() {
        TestConfigSource.defineConfigValue("0h");
        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(10); // Default Value
    }

    @Test
    public void getSSOCookieTimeToLive_negative() {
        TestConfigSource.defineConfigValue("-1D");
        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(10); // Default Value
    }

}