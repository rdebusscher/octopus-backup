package be.c4j.ee.security.credentials.authentication.oauth2.google;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2ProviderMetaData;
import be.c4j.ee.security.credentials.authentication.oauth2.info.OAuth2InfoProvider;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
public class GoogleProviderMetaData implements OAuth2ProviderMetaData {

    @Inject
    @GoogleProvider
    private OAuth2InfoProvider infoProvider;

    @Override
    public String getServletPath() {
        return "/googleplus";
    }

    @Override
    public String getName() {
        return "Google";
    }

    @Override
    public OAuth2InfoProvider getInfoProvider() {
        return infoProvider;
    }


}
