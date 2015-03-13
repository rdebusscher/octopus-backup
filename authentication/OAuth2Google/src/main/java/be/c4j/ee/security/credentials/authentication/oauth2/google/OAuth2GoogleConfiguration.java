package be.c4j.ee.security.credentials.authentication.oauth2.google;

import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.credentials.authentication.oauth2.google.application.ApplicationInfo;
import be.c4j.ee.security.credentials.authentication.oauth2.google.servlet.GooglePlusServlet;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import be.rubus.web.jerry.provider.BeanProvider;

import javax.enterprise.inject.Specializes;

/**
 *
 */
@Specializes
public class OAuth2GoogleConfiguration extends OctopusConfig {

    @Override
    public String getLoginPage() {
        String result = "";
        ApplicationInfo applicationInfo = BeanProvider.getContextualReference(ApplicationInfo.class, true);
        if (applicationInfo != null) {
            result = '?' + GooglePlusServlet.APPLICATION + '=' + applicationInfo.getName();
        }
        return "/googleplus" + result;
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
