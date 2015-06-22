package be.c4j.ee.security.config;

import org.apache.deltaspike.core.impl.config.BaseConfigSource;
import org.apache.deltaspike.core.util.PropertyFileUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 *
 */
public class OctopusConfigSource extends BaseConfigSource {

    private Properties properties;

    public void loadProperties() {

        String configFile = System.getProperty("octopus.cfg");
        try {
            if (configFile != null) {
                properties = PropertyFileUtils.loadProperties(new URL(configFile));

            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
            // FIXME Logger
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
