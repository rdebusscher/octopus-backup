package be.c4j.ee.security.credentials.authentication.fake;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2Configuration;
import be.c4j.ee.security.credentials.authentication.oauth2.application.CustomCallbackProvider;
import be.c4j.ee.security.credentials.authentication.oauth2.fake.FakeCallbackHandler;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.slf4j.Logger;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
@ApplicationScoped
public class OctopusHandleFakeCallback implements FakeCallbackHandler {

    @Inject
    private Logger logger;

    private CustomCallbackProvider customCallbackProvider;

    @Inject
    private OAuth2TokenStore tokenStore;

    @PostConstruct
    public void init() {
        customCallbackProvider = BeanProvider.getContextualReference(CustomCallbackProvider.class, false);
    }

    public void doAuthenticate(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String applicationName = request.getParameter(OAuth2Configuration.APPLICATION);

        if (customCallbackProvider != null) {
            String callbackURL = customCallbackProvider.determineApplicationCallbackURL(applicationName);

            String userParameter = request.getParameter("user");
            response.sendRedirect(callbackURL + "?token=" + tokenStore.retrieveToken(userParameter));
        } else {
            logger.warn("Fake login could not be completes as there is no CDI instance for CustomCallbackProvider found");
        }
    }
}
