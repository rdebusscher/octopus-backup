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
package be.c4j.ee.security.sso.servlet;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.sso.client.SSOClientConfiguration;
import com.github.scribejava.core.model.OAuth2AccessToken;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.web.util.SavedRequest;
import org.apache.shiro.web.util.WebUtils;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import java.io.IOException;

/**
 * FIXME Remove and use Octopus-sso-client (together wth server module)
 */
@WebServlet(urlPatterns = "/octopusSSOCallback")
public class SSOCallbackServlet extends HttpServlet {

    @Inject
    private SSOClientConfiguration octopusConfig;

    private Client client;

    @Override
    public void init() throws ServletException {
        super.init();

        client = ClientBuilder.newClient();

    }

    @Override
    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {

        HttpSession sess = httpServletRequest.getSession();
        String oAuth2Token = httpServletRequest.getParameter("token");

        String provider = httpServletRequest.getParameter("provider");
        if (provider == null || provider.isEmpty()) {
            provider = "Google";  // Backwards compatibility
        }

        WebTarget target = client.target(octopusConfig.getSSOServer() + "/OAuth2/user/info");
        OAuth2User oAuth2User = target.request()
                .accept(MediaType.APPLICATION_JSON)
                .header("token", oAuth2Token)
                .header("provider", provider)
                .get(OAuth2User.class);

        try {
            oAuth2User.setToken(new OAuth2AccessToken(oAuth2Token, ""));
            SecurityUtils.getSubject().login(oAuth2User);

            SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(httpServletRequest);

            try {
                httpServletResponse.sendRedirect(savedRequest != null ? savedRequest.getRequestUrl() : getRootUrl(httpServletRequest));
            } catch (IOException e) {
                // OWASP A6 : Sensitive Data Exposure
                throw new OctopusUnexpectedException(e);

            }


        } catch (AuthenticationException e) {
            sess.setAttribute(OAuth2User.OAUTH2_USER_INFO, oAuth2User);
            sess.setAttribute("AuthenticationExceptionMessage", e.getMessage());
            try {
                httpServletResponse.sendRedirect(httpServletRequest.getContextPath() + octopusConfig.getUnauthorizedExceptionPage());
            } catch (IOException ioException) {
                // OWASP A6 : Sensitive Data Exposure
                throw new OctopusUnexpectedException(ioException);

            }
        }

    }

    private String getRootUrl(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getContextPath();
    }

}
