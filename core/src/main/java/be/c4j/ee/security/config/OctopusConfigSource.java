/*
 * Copyright 2014-2015 Rudy De Busscher (www.c4j.be)
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
 *
 */
package be.c4j.ee.security.config;

import org.apache.deltaspike.core.impl.config.BaseConfigSource;
import org.apache.deltaspike.core.util.PropertyFileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 *
 */
public class OctopusConfigSource extends BaseConfigSource {

    protected static final Logger LOGGER = LoggerFactory.getLogger(OctopusConfigSource.class);

    private Properties properties;

    public void loadProperties() {

        String configFile = System.getProperty("octopus.cfg");
        try {
            if (configFile != null) {
                properties = PropertyFileUtils.loadProperties(new URL(configFile));

            }
        } catch (MalformedURLException e) {
            LOGGER.error("unable to read configuration from : " + configFile, e);
        } finally {
            if (properties == null) {
                properties = new Properties();
            }
        }

    }

    @Override
    public String getPropertyValue(String key) {
        return properties.getProperty(key);
    }

    @Override
    public Map<String, String> getProperties() {
        Map<String, String> result = new HashMap<String, String>();
        for (String propertyName : properties.stringPropertyNames()) {
            result.put(propertyName, properties.getProperty(propertyName));
        }

        return result;
    }

    @Override
    public boolean isScannable() {
        return true;
    }

    @Override
    public String getConfigName() {
        return "Octopus-configuration";
    }

    @Override
    public int getOrdinal() {
        return 100;
    }
}
