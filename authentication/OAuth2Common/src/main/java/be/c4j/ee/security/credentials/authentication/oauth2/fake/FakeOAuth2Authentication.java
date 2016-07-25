package be.c4j.ee.security.credentials.authentication.oauth2.fake;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

/**
 *
 */
public interface FakeOAuth2Authentication {
    boolean forwardForTokenCreation(ServletContext servletContext, ServletRequest request, ServletResponse response, String userParameter);
}