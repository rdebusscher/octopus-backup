/*
 * Copyright 2014-2017 Rudy De Busscher (www.c4j.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.c4j.ee.security.test;

import be.c4j.ee.security.OctopusConstants;
import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.util.URLUtil;
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

    @Inject
    private URLUtil urlUtil;

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

            if (uri.getScheme() == null) {
                String root = urlUtil.determineRoot(httpServletRequest);
                uri = new URI(root + octopusConfig.getLoginPage());
            }
            String redirectURL = null;
            String path = uri.getPath();
            int idx = -1;
            if (path != null) {
                idx = path.indexOf("/", 1);
                if (idx == -1) {
                    idx = 0; // app deployed without root
                }
            }
            if (idx != -1) {
                if (uri.getPort() == -1) {
                    redirectURL = String.format("%s://%s%s/octopus/testAuthentication", uri.getScheme(), uri.getHost(), path.substring(0, idx));
                } else {
                    redirectURL = String.format("%s://%s:%s%s/octopus/testAuthentication", uri.getScheme(), uri.getHost(), uri.getPort(), path.substring(0, idx));
                }
            }
            if (redirectURL == null) {
                // This would mean that we are unable to retrieve path information of this servlet.
                // But protects to sending a redirect to some unknown URL.
                throw new OctopusUnexpectedException("Unable to determine the redirect URL within the 'doTestAuthenticationServlet'");
            }
            httpServletResponse.sendRedirect(redirectURL + '?' + OctopusConstants.OCTOPUS_REFERER + '=' + URLEncoder.encode(httpServletRequest.getRequestURL().toString(), RedirectView.DEFAULT_ENCODING_SCHEME));

        } catch (URISyntaxException e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new OctopusUnexpectedException(e);

        }
    }
}
