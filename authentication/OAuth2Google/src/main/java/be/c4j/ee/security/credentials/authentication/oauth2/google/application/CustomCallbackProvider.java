package be.c4j.ee.security.credentials.authentication.oauth2.google.application;

/**
 *
 */
public interface CustomCallbackProvider {

    String determineApplicationCallbackURL(String applicationName);
}
