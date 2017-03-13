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
package be.c4j.test;

import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.apache.deltaspike.core.spi.config.ConfigSource;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Describe in this block the functionality of the class.
 * Created by rubus on 10/03/17.
 */

public class TestConfigSource implements ConfigSource {

    private String configValue;
    private Map<String, String> configValues;

    private TestConfigSource(String configValue) {
        this.configValue = configValue;
    }

    private TestConfigSource(Map<String, String> configValues) {
        this.configValues = configValues;
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
        if (configValues == null) {
            return configValue;
        } else {
            return configValues.get(key);
        }
    }

    @Override
    public String getConfigName() {
        return null;
    }

    @Override
    public boolean isScannable() {
        return false;
    }

    public static void defineConfigValue(String configValue) {
        List<ConfigSource> configSources = new ArrayList<ConfigSource>();
        configSources.add(new TestConfigSource(configValue));
        ConfigResolver.addConfigSources(configSources);
    }

    public static void defineConfigValue(Map<String, String> configValues) {
        List<ConfigSource> configSources = new ArrayList<ConfigSource>();
        configSources.add(new TestConfigSource(configValues));
        ConfigResolver.addConfigSources(configSources);
    }

}