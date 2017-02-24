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
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.session.SessionUtil;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.SSOFlow;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import be.c4j.ee.security.sso.client.debug.DebugClientResponseFilter;
import be.c4j.ee.security.sso.encryption.SSODataEncryptionHandler;
import be.c4j.ee.security.sso.rest.DefaultPrincipalUserInfoJSONProvider;
import be.c4j.ee.security.sso.rest.PrincipalUserInfoJSONProvider;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.web.util.SavedRequest;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import javax.ws.rs.core.Response;
import java.io.IOException;

/**
 *
 */
@WebServlet("/octopus/sso/SSOCallback")
public class SSOCallbackServlet extends HttpServlet {

    private static final String OAUTH2_STATE = "state";
    private Logger logger = LoggerFactory.getLogger(SSOCallbackServlet.class);

    @Inject
    private OctopusSSOClientConfiguration config;

    @Inject
    private OctopusConfig octopusConfig;

    @Inject
    private SessionUtil sessionUtil;

    private SSODataEncryptionHandler encryptionHandler;

    private PrincipalUserInfoJSONProvider userInfoJSONProvider;

    private Client client;

    @Override
    public void init() throws ServletException {

        client = ClientBuilder.newClient();

        if (octopusConfig.showDebugFor().contains(Debug.SSO_REST)) {
            client.register(DebugClientResponseFilter.class);
        }

        encryptionHandler = BeanProvider.getContextualReference(SSODataEncryptionHandler.class, true);

        userInfoJSONProvider = BeanProvider.getContextualReference(PrincipalUserInfoJSONProvider.class, true);
        if (userInfoJSONProvider == null) {
            userInfoJSONProvider = new DefaultPrincipalUserInfoJSONProvider();
        }

    }

    @Override
    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {

        checkState(httpServletRequest);

        String realToken = retrieveToken(httpServletRequest);
        showDebugInfo(realToken);

        WebTarget target = client.target(config.getSSOServer() + "/" + config.getSSOEndpointRoot() + "/octopus/sso/user");

        Response response = target.request()
                .header("Authorization", "Bearer " + defineToken(realToken))
                .accept(MediaType.APPLICATION_JSON)
                .get();

        String json = response.readEntity(String.class);
        if (response.getStatus() == 200) {

            OctopusSSOUser user = OctopusSSOUser.fromJSON(json, userInfoJSONProvider);

            user.setToken(realToken);

            try {

                sessionUtil.invalidateCurrentSession(httpServletRequest);

                SecurityUtils.getSubject().login(user);

                SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(httpServletRequest);
                try {
                    httpServletResponse.sendRedirect(savedRequest != null ? savedRequest.getRequestUrl() : httpServletRequest.getContextPath());
                } catch (IOException e) {
                    // OWASP A6 : Sensitive Data Exposure
                    throw new OctopusUnexpectedException(e);

                }

            } catch (UnauthorizedException e) {
                handleException(httpServletRequest, httpServletResponse, e, user);
            }
        } else {
            logger.warn(String.format("Retrieving SSO User info failed with status %s and body %s", String.valueOf(response.getStatus()), json));
        }

        response.close();

    }

    private void checkState(HttpServletRequest httpServletRequest) {
        HttpSession session = httpServletRequest.getSession(true);
        Object expectedState = session.getAttribute(OAUTH2_STATE);
        String state = httpServletRequest.getParameter(OAUTH2_STATE);

        session.removeAttribute(OAUTH2_STATE);
        if (!expectedState.equals(state)) {
            logger.warn("Received request with incorrect 'state' value");
            throw new AuthorizationException("Failed to validate the request");
        }
    }

    private void showDebugInfo(String token) {

        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("Call SSO Server for User info (token = %s)", token));
        }
    }

    private void handleException(HttpServletRequest request, HttpServletResponse resp, Throwable e, OctopusSSOUser user) {
        HttpSession sess = request.getSession();
        sess.setAttribute(OctopusSSOUser.class.getSimpleName(), user);
        sess.setAttribute("AuthenticationExceptionMessage", e.getMessage());
        // The SSOAfterSuccessfulLoginHandler found that the user doesn't have the required access permission
        try {
            resp.sendRedirect(request.getContextPath() + config.getUnauthorizedExceptionPage());
        } catch (IOException ioException) {
            // OWASP A6 : Sensitive Data Exposure
            throw new OctopusUnexpectedException(ioException);

        }
        sess.invalidate();
    }

    private String defineToken(String token) {
        String result;
        if (encryptionHandler != null) {
            result = encryptionHandler.encryptData(token, null);
        } else {
            result = token;
        }
        return result;
    }

    private String retrieveToken(HttpServletRequest req) {
        SSOFlow ssoType = config.getSSOType();

        String token = "";
        switch (ssoType) {

            case IMPLICIT:
                token = req.getParameter("access_token");
                break;
            case AUTHORIZATION_CODE:
                token = req.getParameter("code");
                break;
        }

        String realToken = token;
        if (ssoType == SSOFlow.IMPLICIT && encryptionHandler != null) {

            realToken = encryptionHandler.decryptData(token, null);

        }
        return realToken;
    }
}
