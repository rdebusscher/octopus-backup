package be.c4j.ee.security.config;

import be.c4j.ee.security.shiro.RestUserFilter;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniSecurityManagerFactory;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class RestConfiguration implements ConfigurationPlugin {
    @Override
    public void addConfiguration(Ini ini) {
        Ini.Section mainSection = ini.get(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        mainSection.put("userRest", RestUserFilter.class.getName());

    }
}
