package be.c4j.ee.scurity.credentials.authentication.oauth2.google;

import be.c4j.ee.scurity.credentials.authentication.oauth2.google.filter.GoogleAuthcFilter;
import be.c4j.ee.scurity.credentials.authentication.oauth2.google.matcher.GoogleCredentialsMatcher;
import be.c4j.ee.security.config.ConfigurationPlugin;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniSecurityManagerFactory;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class OAuth2GoogleConfigurationPlugin implements ConfigurationPlugin {
    private void setGoogleBasedMatcher(Ini ini) {
        Ini.Section mainSection = ini.get(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        mainSection.put("credentialsMatcher", GoogleCredentialsMatcher.class.getName());
        mainSection.put("appRealm.credentialsMatcher", "$credentialsMatcher");

        mainSection.put("GoogleAuthcFilter", GoogleAuthcFilter.class.getName());
    }

    @Override
    public void addConfiguration(Ini ini) {
        setGoogleBasedMatcher(ini);
    }
}
