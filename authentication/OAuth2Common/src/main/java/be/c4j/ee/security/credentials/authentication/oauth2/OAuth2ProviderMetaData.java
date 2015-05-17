package be.c4j.ee.security.credentials.authentication.oauth2;

import be.c4j.ee.security.credentials.authentication.oauth2.info.OAuth2InfoProvider;

/**
 *
 */
public interface OAuth2ProviderMetaData {

    String getServletPath();

    String getName();

    OAuth2InfoProvider getInfoProvider();
}
