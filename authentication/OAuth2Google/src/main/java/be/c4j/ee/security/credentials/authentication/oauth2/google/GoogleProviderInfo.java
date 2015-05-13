package be.c4j.ee.security.credentials.authentication.oauth2.google;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2ProviderInfo;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class GoogleProviderInfo implements OAuth2ProviderInfo {
    @Override
    public String getServletPath() {
        return "/googleplus";
    }

    @Override
    public String getName() {
        return "Google";
    }
}
