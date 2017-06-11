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
package be.c4j.ee.security.sso.client.callback;

import be.c4j.ee.security.config.Debug;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.session.ApplicationUsageController;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.SSOFlow;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
@WebServlet("/octopus/sso/SSOLogoutCallback")
public class SSOLogoutCallbackServlet extends HttpServlet {

    private static final Logger LOGGER = LoggerFactory.getLogger(SSOLogoutCallbackServlet.class);

    @Inject
    private OctopusConfig octopusConfig;

    @Inject
    private OctopusSSOClientConfiguration config;

    @Inject
    private ApplicationUsageController applicationUsageController;

    @Override
    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {

        final String realToken = retrieveToken(httpServletRequest);

        applicationUsageController.invalidateSession(new ApplicationUsageController.UserSessionFinder() {
            @Override
            public boolean isCorrectPrincipal(UserPrincipal userPrincipal, String sessionId) {
                boolean result = false;
                Object token = userPrincipal.getUserInfo("token");
                if (token instanceof OctopusSSOUser) {
                    OctopusSSOUser ssoUser = (OctopusSSOUser) token;
                    result = ssoUser.getAccessToken().equals(realToken);
                }
                return result;
            }
        });
        showDebugInfo(realToken);
    }

    private String retrieveToken(HttpServletRequest req) {
        SSOFlow ssoType = config.getSSOType();

        String token = req.getParameter("access_token");

        String realToken = token;
        return realToken;
    }

    private void showDebugInfo(String token) {

        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            LOGGER.info(String.format("SSO Server requested logout of User (token = %s)", token));
        }
    }
}
