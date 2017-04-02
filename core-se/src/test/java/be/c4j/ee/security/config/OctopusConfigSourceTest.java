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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import uk.org.lidalia.slf4jext.Level;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class OctopusConfigSourceTest {

    private OctopusConfigSource configSource;

    @Before
    public void setup() {
        configSource = new OctopusConfigSource();
    }

    @After
    public void clearLoggers() {
        TestLoggerFactory.clear();
    }

    @Test
    public void loadProperties() {
        String configFile = this.getClass().getResource("/testConfig.properties").toExternalForm();
        System.setProperty("octopus.cfg", configFile);

        configSource.loadProperties();
        String value = configSource.getPropertyValue("key");
        assertThat(value).isEqualTo("value");
    }

    @Test
    public void getProperties() {

        String configFile = this.getClass().getResource("/testConfig.properties").toExternalForm();
        System.setProperty("octopus.cfg", configFile);

        configSource.loadProperties();

        Map<String, String> properties = configSource.getProperties();
        assertThat(properties).containsEntry("key", "value");
        assertThat(properties).containsEntry("tester", "JUnit");
    }

    @Test
    public void loadProperties_NoConfigSpecified() {
        System.clearProperty("octopus.cfg");

        configSource.loadProperties();
        assertThat(configSource.getProperties()).isEmpty();
    }

    @Test
    public void loadProperties_WrongFileName() {
        TestLogger logger = TestLoggerFactory.getTestLogger(OctopusConfigSource.class);

        String configFile = this.getClass().getResource("/testConfig.properties").toExternalForm();
        System.setProperty("octopus.cfg", configFile.substring(0, configFile.length() - 5));  // Create a non existing file name

        configSource.loadProperties();
        assertThat(configSource.getProperties()).isEmpty();

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.ERROR);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).startsWith("Unable to read configuration from : file:");
    }


}