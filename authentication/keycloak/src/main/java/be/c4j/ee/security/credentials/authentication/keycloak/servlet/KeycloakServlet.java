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
package be.c4j.ee.security.credentials.authentication.keycloak.servlet;

import be.c4j.ee.security.authentication.ActiveSessionRegistry;
import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.ee.security.credentials.authentication.keycloak.config.KeycloakConfiguration;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.session.SessionUtil;
import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.AdapterUtils;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.constants.AdapterConstants;
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
@WebServlet("/keycloak/*")
public class KeycloakServlet extends HttpServlet {

    @Inject
    private Logger logger;

    @Inject
    private OctopusJSFConfig octopusConfig;

    @Inject
    private KeycloakConfiguration keycloakConfiguration;

    @Inject
    private ActiveSessionRegistry activeSessionRegistry;

    @Inject
    private SessionUtil sessionUtil;

    private KeycloakDeployment oidcDeployment;

    @Override
    public void init() throws ServletException {
        oidcDeployment = keycloakConfiguration.getKeycloakDeployment();
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        OIDCAdapter adapter = new OIDCAdapter(oidcDeployment, request, response, octopusConfig, keycloakConfiguration, activeSessionRegistry, sessionUtil);
        String code = adapter.getCode();
        if (code == null) {

            String state = AdapterUtils.generateId();
            request.getSession().setAttribute(OAuth2Constants.STATE, state);

            String redirectUri = adapter.getRedirectUri(state);
            try {
                response.sendRedirect(redirectUri);
            } catch (IOException e) {
                // OWASP A6 : Sensitive Data Exposure
                throw new OctopusUnexpectedException(e);

            }
        } else {
            try {
                adapter.authenticate(code);
            } catch (IOException e) {
                // OWASP A6 : Sensitive Data Exposure
                throw new OctopusUnexpectedException(e);

            }
        }

    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        OIDCActions oidcActions = new OIDCActions(oidcDeployment, request, response, activeSessionRegistry);
        handleRequest(oidcActions);
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        OIDCActions oidcActions = new OIDCActions(oidcDeployment, request, response, activeSessionRegistry);
        handleRequest(oidcActions);
    }

    protected boolean handleRequest(OIDCActions oidcActions) {
        String requestUri = oidcActions.getURI();
        logger.debug("adminRequest {0}", requestUri);
        if (oidcActions.preflightCors()) {
            return true;
        }
        if (requestUri.endsWith(AdapterConstants.K_LOGOUT)) {
            oidcActions.handleLogout();
            return true;
        } else if (requestUri.endsWith(AdapterConstants.K_PUSH_NOT_BEFORE)) {
            oidcActions.handlePushNotBefore();
            return true;
        } else if (requestUri.endsWith(AdapterConstants.K_VERSION)) {
            oidcActions.handleVersion();
            return true;
        } else if (requestUri.endsWith(AdapterConstants.K_TEST_AVAILABLE)) {
            oidcActions.handleTestAvailable();
            return true;
        }
        return false;
    }

}
