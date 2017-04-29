package be.c4j.ee.security.test;

import be.c4j.ee.security.OctopusConstants;
import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.web.util.RedirectView;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;

/**
 *
 */
@WebServlet("/doTestAuthentication")
public class DoTestAuthenticationServlet extends HttpServlet {

    @Inject
    private OctopusJSFConfig octopusConfig;

    private AuthenticatedPageInfo authenticatedPageInfo;

    @Override
    public void init() throws ServletException {
        super.init();
        authenticatedPageInfo = BeanProvider.getContextualReference(AuthenticatedPageInfo.class, true);
        // optional true so that we can show a proper error message
        if (authenticatedPageInfo == null) {
            throw new OctopusConfigurationException("You need to implement AuthenticatedPageInfo interface as a CDI bean in order to make use of the 'doTestAuthentication' servlet");
        }
    }

    @Override
    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {

        String authenticated = httpServletRequest.getParameter(OctopusConstants.OCTOPUS_AUTHENTICATED);
        if (authenticated != null) {
            Boolean isAuthenticated = Boolean.valueOf(authenticated);
            if (isAuthenticated) {
                httpServletResponse.sendRedirect(authenticatedPageInfo.getAuthenticatedPage());
            } else {
                httpServletResponse.sendRedirect(authenticatedPageInfo.getUnauthenticatedPage());

            }

        } else {
            sendTestRedirect(httpServletRequest, httpServletResponse);
        }
    }

    private void sendTestRedirect(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException {
        try {
            URI uri = new URI(octopusConfig.getLoginPage());

            String redirectURL = null;
            String path = uri.getPath();
            int idx = -1;
            if (path != null) {
                idx = path.indexOf("/", 1);
            }
            if (idx != -1) {
                if (uri.getPort() == -1) {
                    redirectURL = String.format("%s://%s%s/testAuthentication", uri.getScheme(), uri.getHost(), path.substring(0, idx));
                } else {
                    redirectURL = String.format("%s://%s:%s%s/testAuthentication", uri.getScheme(), uri.getHost(), uri.getPort(), path.substring(0, idx));
                }
            }
            httpServletResponse.sendRedirect(redirectURL + '?' + OctopusConstants.OCTOPUS_REFERER + '=' + URLEncoder.encode(httpServletRequest.getRequestURL().toString(), RedirectView.DEFAULT_ENCODING_SCHEME));

        } catch (URISyntaxException e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new OctopusUnexpectedException(e);

        }
    }
}
