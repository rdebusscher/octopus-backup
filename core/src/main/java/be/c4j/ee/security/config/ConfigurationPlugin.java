package be.c4j.ee.security.config;

import org.apache.shiro.config.Ini;

/**
 *
 */
public interface ConfigurationPlugin {

    void addConfiguration(Ini ini);
}
