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