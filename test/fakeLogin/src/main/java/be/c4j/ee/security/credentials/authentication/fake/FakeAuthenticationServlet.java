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
package be.c4j.ee.security.credentials.authentication.fake;

import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.fake.LoginAuthenticationTokenProvider;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.apache.deltaspike.security.api.authorization.AccessDeniedException;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.web.util.SavedRequest;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
@WebServlet("/fakeLogin")
public class FakeAuthenticationServlet extends HttpServlet {

    @Inject
    private Logger logger;

    @Inject
    private OctopusJSFConfig octopusConfig;

    @Inject
    private LoginAuthenticationTokenProvider loginAuthenticationTokenProvider;

    private Boolean localhostOnly;

    @Override
    public void init() throws ServletException {
        // TODO Documentation
        localhostOnly = Boolean.valueOf(ConfigResolver.getPropertyValue("fakeLogin.localhostOnly", "true"));
        if (localhostOnly == null) {
            localhostOnly = Boolean.TRUE;
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        if (localhostOnly && !"localhost".equals(request.getServerName())) {
            throw new AccessDeniedException(null);
        }

        String loginData = request.getParameter("loginData");

        AuthenticationToken token = loginAuthenticationTokenProvider.determineAuthenticationToken(loginData);

        if (token == null) {
            throw new OctopusConfigurationException("LoginAuthenticationTokenProvider implementation returns null which is not allowed");
        }

        try {

            // Here we do not need to invalidate the current session as it is only for development purposes.

            SecurityUtils.getSubject().login(token);

            SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(request);
            try {
                response.sendRedirect(savedRequest != null ? savedRequest.getRequestUrl() : request.getContextPath());
            } catch (IOException e) {
                // OWASP A6 : Sensitive Data Exposure
                throw new OctopusUnexpectedException(e);

            }
        } catch (AuthenticationException e) {
            logger.error(e.getMessage());
            // DataSecurityProvider decided that google user has no access to application
            request.getSession().setAttribute("AuthenticationExceptionMessage", e.getMessage());
            try {
                response.sendRedirect(request.getContextPath() + octopusConfig.getUnauthorizedExceptionPage());
            } catch (IOException ioException) {
                // OWASP A6 : Sensitive Data Exposure
                throw new OctopusUnexpectedException(ioException);

            }
        }

    }
}
