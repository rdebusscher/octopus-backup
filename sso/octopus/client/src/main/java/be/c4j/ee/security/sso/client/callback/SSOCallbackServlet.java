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
import be.c4j.ee.security.sso.client.OpenIdVariableClientData;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import be.c4j.ee.security.sso.encryption.SSODataEncryptionHandler;
import be.c4j.ee.security.sso.rest.DefaultPrincipalUserInfoJSONProvider;
import be.c4j.ee.security.sso.rest.PrincipalUserInfoJSONProvider;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.nimbusds.openid.connect.sdk.validators.IDTokenClaimsVerifier;
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
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 *
 */
@WebServlet("/octopus/sso/SSOCallback")
public class SSOCallbackServlet extends HttpServlet {

    private Logger logger = LoggerFactory.getLogger(SSOCallbackServlet.class);

    @Inject
    private OctopusSSOClientConfiguration config;

    @Inject
    private OctopusConfig octopusConfig;

    @Inject
    private SessionUtil sessionUtil;

    private SSODataEncryptionHandler encryptionHandler;

    private PrincipalUserInfoJSONProvider userInfoJSONProvider;

    @Override
    public void init() throws ServletException {

        encryptionHandler = BeanProvider.getContextualReference(SSODataEncryptionHandler.class, true);

        userInfoJSONProvider = BeanProvider.getContextualReference(PrincipalUserInfoJSONProvider.class, true);
        if (userInfoJSONProvider == null) {
            userInfoJSONProvider = new DefaultPrincipalUserInfoJSONProvider();
        }

    }

    @Override
    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {

        String query = httpServletRequest.getQueryString();
        AuthenticationResponse authenticationResponse = null;
        try {
            URI responseURL = new URI("?" + query);

            authenticationResponse = AuthenticationResponseParser.parse(responseURL);
        } catch (URISyntaxException e) {
            // FIXME
            e.printStackTrace();
        } catch (ParseException e) {
            // FIXME
            e.printStackTrace();
        }

        if (authenticationResponse instanceof AuthenticationErrorResponse) {
            // FIXME
            return;
        }
        AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authenticationResponse;

        HttpSession session = httpServletRequest.getSession(true);

        OpenIdVariableClientData variableClientData = (OpenIdVariableClientData) session.getAttribute(OpenIdVariableClientData.class.getName());

        checkState(variableClientData, authenticationResponse.getState());

        // FIXME, check authenticaion code flow or implicit flow

        AuthorizationCode authorizationCode = successResponse.getAuthorizationCode();

        showDebugInfo(authorizationCode.getValue());

        BearerAccessToken accessToken = null;
        try {
            URI redirectURI = new URI(variableClientData.getRootURL() + "/octopus/sso/SSOCallback");
            AuthorizationCodeGrant grant = new AuthorizationCodeGrant(authorizationCode, redirectURI);
            ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID(config.getSSOClientId()), new Secret("secret"));

            TokenRequest tokenRequest = new TokenRequest(new URI(config.getTokenEndpoint()), clientAuth, grant, null);

            HTTPResponse response = tokenRequest.toHTTPRequest().send();
            TokenResponse tokenResponse = OIDCTokenResponseParser.parse(response);


            if (tokenResponse instanceof OIDCTokenResponse) {
                OIDCTokenResponse oidcResponse = (OIDCTokenResponse) tokenResponse;
                OIDCTokens oidcTokens = oidcResponse.getOIDCTokens();

                JWT idToken = oidcTokens.getIDToken();
                System.out.println(idToken);

                IDTokenClaimsSet tokenClaimsSet = new IDTokenClaimsSet(idToken.getJWTClaimsSet());

                System.out.println(tokenClaimsSet.getAudience().get(0));

                accessToken = oidcTokens.getBearerAccessToken();

                IDTokenClaimsVerifier claimsVerifier = new IDTokenClaimsVerifier(new Issuer(config.getSSOServer()), new ClientID(config.getSSOClientId()), variableClientData.getNonce(), 0);
                claimsVerifier.verify(idToken.getJWTClaimsSet());
            }

        } catch (URISyntaxException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (java.text.ParseException e) {
            e.printStackTrace();
        } catch (BadJWTException e) {
            e.printStackTrace();
        }

        try {
            UserInfoRequest infoRequest = new UserInfoRequest(new URI(config.getUserInfoEndpoint()), accessToken);

            HTTPResponse response = infoRequest.toHTTPRequest().send();
            String json = response.getContent();

            OctopusSSOUser user = OctopusSSOUser.fromJSON(json, userInfoJSONProvider);

            user.setBearerAccessToken(accessToken);
            //user.setToken(code);

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

        } catch (URISyntaxException e) {
            e.printStackTrace();
        }


                /*
        WebTarget target = client.target(config.getSSOServer() + "/" + config.getSSOEndpointRoot() + "/octopus/sso/user");

        Response response = target.request()
                .header("Authorization", "Bearer " + defineToken(code))
                .accept(MediaType.APPLICATION_JSON)
                .get();

        String json = response.readEntity(String.class);
        if (response.getStatus() == 200) {

            OctopusSSOUser user = OctopusSSOUser.fromJSON(json, userInfoJSONProvider);

            user.setToken(code);

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
*/
    }

    private void checkState(OpenIdVariableClientData variableClientData, State state) {

        if (!variableClientData.getState().equals(state)) {
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
