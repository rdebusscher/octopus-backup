/*
 * Copyright 2014-2015 Rudy De Busscher (www.c4j.be)
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
 *
 */
package be.c4j.ee.security.sso.servlet;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.sso.client.SSOClientConfiguration;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.web.util.SavedRequest;
import org.apache.shiro.web.util.WebUtils;
import org.scribe.model.Token;

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
 *
 */
@WebServlet(urlPatterns = "/octopusSSOCallback")
public class SSOCallbackServlet extends HttpServlet {

    @Inject
    private SSOClientConfiguration octopusConfig;

    @Override
    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {

        HttpSession sess = httpServletRequest.getSession();
        String oAuth2Token = httpServletRequest.getParameter("token");

        Client client = ClientBuilder.newClient();

        WebTarget target = client.target(octopusConfig.getSSOServer() + "/OAuth2/info");
        OAuth2User oAuth2User = target.request()
                .accept(MediaType.APPLICATION_JSON)
                .header("token", oAuth2Token)
                .header("provider", "Google")  // TODO
                .get(OAuth2User.class);

        try {
            oAuth2User.setToken(new Token(oAuth2Token, ""));
            SecurityUtils.getSubject().login(oAuth2User);

            SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(httpServletRequest);

            httpServletResponse.sendRedirect(savedRequest != null ? savedRequest.getRequestUrl() : getRootUrl(httpServletRequest));


        } catch (AuthenticationException e) {
            //sess.setAttribute("googleUser", googleUser);
            sess.setAttribute("AuthenticationExceptionMessage", e.getMessage());
            // DataSecurityProvider decided that google user has no access to application
            httpServletResponse.sendRedirect(httpServletRequest.getContextPath() + octopusConfig.getUnauthorizedExceptionPage());
        }

    }

    private String getRootUrl(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getContextPath();
    }

}
