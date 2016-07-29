package be.c4j.ee.security.credentials.authentication.fake;

import be.c4j.ee.security.credentials.authentication.oauth2.fake.FakeOAuth2Authentication;
import be.c4j.ee.security.credentials.authentication.oauth2.fake.FakeUserCheck;
import be.c4j.ee.security.credentials.authentication.oauth2.servlet.OAuth2CallbackServlet;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.enterprise.context.ApplicationScoped;
import javax.servlet.*;
import java.io.IOException;

/**
 *
 */
@ApplicationScoped
public class OctopusFakeOAuth2Authentication implements FakeOAuth2Authentication {

    public boolean forwardForTokenCreation(ServletContext servletContext, ServletRequest request, ServletResponse response, String userParameter) {

        boolean result = false;

        FakeUserCheck fakeUserCheck = BeanProvider.getContextualReference(FakeUserCheck.class, true);
        if (fakeUserCheck != null) {
            result = fakeUserCheck.checkFakeUser(userParameter);
        }
        if (result) {
            RequestDispatcher dispatcher = servletContext.getRequestDispatcher("/oauth2callback");
            request.setAttribute("code", "fake");  // TODO Probably this is only for Google
            request.setAttribute(OAuth2CallbackServlet.FAKE_MARKER, "true");
            try {
                dispatcher.forward(request, response);
            } catch (ServletException e) {
                // FIXME
                e.printStackTrace();
            } catch (IOException e) {
                // FIXME
                e.printStackTrace();
            }
        }
        return result;
    }
}
