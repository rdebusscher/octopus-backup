package be.c4j.ee.security.credentials.authentication.oauth2.fake;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
public interface FakeCallbackHandler {
    void doAuthenticate(HttpServletRequest request, HttpServletResponse response) throws IOException;
}
