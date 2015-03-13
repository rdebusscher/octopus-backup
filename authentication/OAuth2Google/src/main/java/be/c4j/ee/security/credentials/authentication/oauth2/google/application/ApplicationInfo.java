package be.c4j.ee.security.credentials.authentication.oauth2.google.application;

/**
 *
 */
public interface ApplicationInfo {
    /**
     * Returns the name of the application. Should never return null or an empty string.
     *
     * @return name of the application
     */
    String getName();
}
