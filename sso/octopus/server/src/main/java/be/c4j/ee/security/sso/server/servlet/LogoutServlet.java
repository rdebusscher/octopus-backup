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
package be.c4j.ee.security.sso.server.servlet;

import be.c4j.ee.security.config.Debug;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.server.config.SSOServerConfiguration;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;
import org.apache.shiro.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */

@WebServlet("/octopus/sso/logout")
public class LogoutServlet extends HttpServlet {

    private Logger logger = LoggerFactory.getLogger(LogoutServlet.class);

    @Inject
    private OctopusSSOUser octopusSSOUser;

    @Inject
    private SSOServerConfiguration ssoServerConfiguration;

    @Inject
    private OctopusJSFConfig jsfConfiguration;

    @Inject
    private OctopusConfig octopusConfig;

    @Inject
    private SSOTokenStore tokenStore;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        tokenStore.removeUser(octopusSSOUser);

        resp.sendRedirect(getLogoutURL(req));

        SecurityUtils.getSubject().logout();  // Will this trigger things we don't want ??

        req.getSession().invalidate();

        showDebugInfo(octopusSSOUser);

    }

    private String getLogoutURL(HttpServletRequest request) {

        String rootUrl = getRootUrl(request);
        String logoutPage = jsfConfiguration.getLogoutPage();
        if (logoutPage.startsWith("/")) {
            rootUrl += logoutPage;
        } else {
            rootUrl = logoutPage;
        }
        return rootUrl;
    }

    private String getRootUrl(HttpServletRequest request) {
        return request.getContextPath();
    }

    private void showDebugInfo(OctopusSSOUser user) {

        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("User %s is logged out (token = %s)", user.getFullName(), user.getToken()));
        }
    }
}