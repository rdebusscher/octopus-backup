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