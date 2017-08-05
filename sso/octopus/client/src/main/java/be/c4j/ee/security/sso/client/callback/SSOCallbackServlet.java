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

import be.c4j.ee.security.authentication.octopus.OctopusSEConfiguration;
import be.c4j.ee.security.authentication.octopus.requestor.OctopusUserRequestor;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.session.SessionUtil;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.OctopusSSOUserConverter;
import be.c4j.ee.security.sso.SSOFlow;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import be.c4j.ee.security.sso.rest.DefaultPrincipalUserInfoJSONProvider;
import be.c4j.ee.security.sso.rest.PrincipalUserInfoJSONProvider;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.UnauthorizedException;
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
@WebServlet("/octopus/sso/SSOCallback")
public class SSOCallbackServlet extends HttpServlet {

    @Inject
    private ExchangeForAccessCode exchangeForAccessCode;

    @Inject
    private CallbackErrorHandler callbackErrorHandler;

    @Inject
    private OctopusSSOUserConverter octopusSSOUserConverter;

    @Inject
    private OctopusSSOClientConfiguration config;

    @Inject
    private OctopusConfig octopusConfig;

    @Inject
    private SessionUtil sessionUtil;

    private OctopusUserRequestor octopusUserRequestor;

    /*
    private PrincipalUserInfoJSONProvider userInfoJSONProvider;
*/

    @Override
    public void init() throws ServletException {

        PrincipalUserInfoJSONProvider userInfoJSONProvider = BeanProvider.getContextualReference(PrincipalUserInfoJSONProvider.class, true);
        if (userInfoJSONProvider == null) {
            userInfoJSONProvider = new DefaultPrincipalUserInfoJSONProvider();
        }

        // new OctopusSEConfiguration() -> A bit weird, but due to Deltaspike config, it reads from the correct configuration
        octopusUserRequestor = new OctopusUserRequestor(new OctopusSEConfiguration(), octopusSSOUserConverter, userInfoJSONProvider);
    }

    @Override
    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {

        SSOCallbackServletHandler handler = new SSOCallbackServletHandler(httpServletRequest, httpServletResponse, callbackErrorHandler);

        // Get the authentication response and do some basic checks about it.
        AuthenticationResponse authenticationResponse = handler.getAuthenticationResponse();

        if (authenticationResponse == null) {
            return;
        }

        AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authenticationResponse;

        BearerAccessToken accessToken = null;

        if (config.getSSOType() == SSOFlow.AUTHORIZATION_CODE) {
            //get AccessToken from AuthorizationCode
            accessToken = handler.getAccessTokenFromAuthorizationCode(successResponse, exchangeForAccessCode);
        }

        if (config.getSSOType() == SSOFlow.IMPLICIT) {
            // We received an AccessToken because of the implicit flow.
            // TODO Is this cast always safe ??
            accessToken = (BearerAccessToken) successResponse.getAccessToken();

            if (accessToken == null) {
                ErrorObject errorObject = new ErrorObject("OCT-SSO-CLIENT-014", "Missing Access code");
                callbackErrorHandler.showErrorMessage(httpServletResponse, errorObject);
            }
        }

        if (accessToken == null) {
            // There was some issue retrieving the accessToken.
            return;
        }

        // Retrieve user info from the accessToken
        OctopusSSOUser user = handler.retrieveUser(octopusUserRequestor, accessToken);

        if (user == null) {
            // There was an issue retrieving the user.
            return;
        }
        try {

            sessionUtil.invalidateCurrentSession(httpServletRequest);

            // Do the login
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

    }

    private void handleException(HttpServletRequest request, HttpServletResponse resp, Throwable e, OctopusSSOUser user) {
        HttpSession sess = request.getSession();
        sess.invalidate();

        // With a new HttpSession.
        sess = request.getSession(true);
        sess.setAttribute(OctopusSSOUser.class.getSimpleName(), user);
        sess.setAttribute("AuthenticationExceptionMessage", e.getMessage());
        // The SSOAfterSuccessfulLoginHandler found that the user doesn't have the required access permission
        try {
            resp.sendRedirect(request.getContextPath() + config.getUnauthorizedExceptionPage());
        } catch (IOException ioException) {
            // OWASP A6 : Sensitive Data Exposure
            throw new OctopusUnexpectedException(ioException);

        }
    }

}
