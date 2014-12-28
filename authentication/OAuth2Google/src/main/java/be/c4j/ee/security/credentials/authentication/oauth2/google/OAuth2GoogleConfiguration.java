package be.c4j.ee.security.credentials.authentication.oauth2.google;

import be.c4j.ee.security.config.OctopusConfig;
import be.rubus.web.jerry.config.logging.ConfigEntry;

import javax.enterprise.inject.Specializes;

/**
 *
 */
@Specializes
public class OAuth2GoogleConfiguration extends OctopusConfig {
    @Override
    public String getLoginPage() {
        return "/googleplus";
    }

    @ConfigEntry
    public String getClientId() {
        return configProperties.getProperty("OAuth2.clientId", "");
    }

    @ConfigEntry
    public String getClientSecret() {
        return configProperties.getProperty("OAuth2.clientSecret", "");
    }
}
