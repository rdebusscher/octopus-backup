package be.c4j.ee.security.credentials.authentication.oracle.credentials.config;

import be.c4j.ee.security.config.ConfigurationPlugin;
import be.c4j.ee.security.credentials.authentication.oracle.OracleCredentialsMatcher;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniSecurityManagerFactory;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class OracleConfiguration implements ConfigurationPlugin {

    private void setOracleBasedMatcher(Ini ini) {
        Ini.Section mainSection = ini.get(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        mainSection.put("credentialsMatcher", OracleCredentialsMatcher.class.getName());
        mainSection.put("appRealm.credentialsMatcher", "$credentialsMatcher");
    }

    @Override
    public void addConfiguration(Ini ini) {
        setOracleBasedMatcher(ini);
    }
}
