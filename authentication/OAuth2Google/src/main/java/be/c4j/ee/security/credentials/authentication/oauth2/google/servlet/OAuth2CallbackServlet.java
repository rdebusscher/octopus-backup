/*
 * Copyright 2014-2016 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.credentials.authentication.oauth2.google.servlet;


import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2Configuration;
import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.credentials.authentication.oauth2.application.CustomCallbackProvider;
import be.c4j.ee.security.credentials.authentication.oauth2.google.GoogleProvider;
import be.c4j.ee.security.credentials.authentication.oauth2.google.json.GoogleJSONProcessor;
import be.c4j.ee.security.credentials.authentication.oauth2.info.OAuth2InfoProvider;
import be.rubus.web.jerry.provider.BeanProvider;
import com.github.scribejava.core.model.Token;
import com.github.scribejava.core.model.Verifier;
import com.github.scribejava.core.oauth.OAuth20Service;
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
import java.io.IOException;

/**
 *
 */
@WebServlet(urlPatterns = {"/oauth2callback"})
public class OAuth2CallbackServlet extends HttpServlet {

    @Inject
    private GoogleJSONProcessor jsonProcessor;

    @Inject
    private OctopusJSFConfig octopusConfig;

    @Inject
    @GoogleProvider
    private OAuth2InfoProvider infoProvider;

    private CustomCallbackProvider customCallbackProvider;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, ServletException {

        //Check if the user have rejected
        String error = req.getParameter("error");
        if ((null != error) && ("access_denied".equals(error.trim()))) {
            HttpSession sess = req.getSession();
            sess.invalidate();
            resp.sendRedirect(req.getContextPath());
            return;
        }

        //OK the user have consented so lets find out about the user

        HttpSession sess = req.getSession();
        OAuth20Service service = (OAuth20Service) sess.getAttribute("oauth2Service");
        String applicationName = getApplicationName(sess);

        //Get the all important authorization code
        String code = req.getParameter("code");
        //Construct the access token
        Token token = service.getAccessToken(new Verifier(code));

        OAuth2User googleUser = infoProvider.retrieveUserInfo(token, req);

        googleUser.setApplicationName(applicationName);
        customCallbackProvider = BeanProvider.getContextualReference(CustomCallbackProvider.class, true);
        String callbackURL = null;
        if (customCallbackProvider != null) {
            callbackURL = customCallbackProvider.determineApplicationCallbackURL(applicationName);
        }
        try {
            SecurityUtils.getSubject().login(googleUser);
            if (callbackURL != null) {
                resp.sendRedirect(callbackURL + "?token=" + token.getToken());

            } else {
                SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(req);
                resp.sendRedirect(savedRequest != null ? savedRequest.getRequestUrl() : req.getContextPath());
            }
        } catch (AuthenticationException e) {
            sess.setAttribute(OAuth2User.OAUTH2_USER_INFO, googleUser);
            sess.setAttribute("AuthenticationExceptionMessage", e.getMessage());
            // DataSecurityProvider decided that google user has no access to application
            resp.sendRedirect(req.getContextPath() + octopusConfig.getUnauthorizedExceptionPage());
        }

    }

    private String getApplicationName(HttpSession sess) {
        return (String) sess.getAttribute(OAuth2Configuration.APPLICATION);
    }
}
