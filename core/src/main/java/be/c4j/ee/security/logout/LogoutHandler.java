package be.c4j.ee.security.logout;

import be.c4j.ee.security.config.OctopusConfig;

import javax.enterprise.context.ApplicationScoped;
import javax.faces.context.ExternalContext;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
public class LogoutHandler {

    @Inject
    private OctopusConfig octopusConfig;

    /* We can create overloaded methods with other types ike ServletRequest to find out at which URL we are running */
    public String getLogoutPage(ExternalContext externalContext) {
        String rootUrl = getRootUrl(externalContext);
        String logoutPage = octopusConfig.getLogoutPage();
        if (logoutPage.startsWith("/")) {
            rootUrl += logoutPage;
        } else {
            rootUrl = logoutPage;
        }
        return rootUrl;
    }

    private String getRootUrl(ExternalContext externalContext) {
        return externalContext.getRequestContextPath();
    }

}
