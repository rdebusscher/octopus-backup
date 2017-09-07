package be.c4j.ee.security.sso.client;

import javax.servlet.http.HttpServletRequest;

/**
 *
 */
public interface ClientCallbackHelper {

    String determineCallbackRoot(HttpServletRequest httpServletRequest);
}
