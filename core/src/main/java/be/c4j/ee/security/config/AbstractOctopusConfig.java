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

import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.apache.deltaspike.core.impl.config.PropertiesConfigSource;
import org.apache.deltaspike.core.spi.config.ConfigSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 *
 */
public class AbstractOctopusConfig {
    private static final String OCTOPUS_CONFIG_PROPERTIES = "octopusConfig.properties";

    protected final Logger LOGGER = LoggerFactory.getLogger(this.getClass());

    protected void defineConfigurationSources() {
        // The properties read from a URL specified by -Doctopus.cfg
        OctopusConfigSource octopusConfigSource = new OctopusConfigSource();
        octopusConfigSource.loadProperties();
        List<ConfigSource> configSourcesToAdd = new ArrayList<ConfigSource>();
        configSourcesToAdd.add(octopusConfigSource);

        //The properties file octopusConfig.properties on the class path
        Properties configProperties = new Properties();
        try {
            InputStream resourceStream = OctopusConfig.class.getClassLoader()
                    .getResourceAsStream(OCTOPUS_CONFIG_PROPERTIES);
            if (resourceStream != null) {
                configProperties.load(resourceStream);


            } else {
                LOGGER.warn("File octopusConfig.properties not found.");
            }
        } catch (IOException e) {
            LOGGER.warn("Exception during reading of the octopusConfig.properties file");
        }

        configSourcesToAdd.add(new PropertiesConfigSource(configProperties) {

            @Override
            public int getOrdinal() {
                return 5;
            }

            @Override
            public String getConfigName() {
                return OCTOPUS_CONFIG_PROPERTIES;
            }
        });

        // Add the 2 additional sources. System properties are already supported by DeltaSpike
        ConfigResolver.addConfigSources(configSourcesToAdd);
    }
}
