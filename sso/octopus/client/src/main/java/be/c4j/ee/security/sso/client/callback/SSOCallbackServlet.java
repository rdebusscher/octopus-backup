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
import be.c4j.ee.security.sso.rest.DefaultPrincipalUserInfoJSONProvider;
import be.c4j.ee.security.sso.rest.PrincipalUserInfoJSONProvider;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.nimbusds.openid.connect.sdk.validators.IDTokenClaimsVerifier;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.SecurityUtils;
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
import java.util.Map;

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

    private PrincipalUserInfoJSONProvider userInfoJSONProvider;

    @Override
    public void init() throws ServletException {

        userInfoJSONProvider = BeanProvider.getContextualReference(PrincipalUserInfoJSONProvider.class, true);
        if (userInfoJSONProvider == null) {
            userInfoJSONProvider = new DefaultPrincipalUserInfoJSONProvider();
        }

    }

    @Override
    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {

        HttpSession session = httpServletRequest.getSession(true);

        OpenIdVariableClientData variableClientData = (OpenIdVariableClientData) session.getAttribute(OpenIdVariableClientData.class.getName());

        AuthenticationResponse authenticationResponse = verifyRequestStructural(httpServletRequest, httpServletResponse, variableClientData);

        if (authenticationResponse == null) {
            return;
        }

        AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authenticationResponse;

        BearerAccessToken accessToken = null;
        if (config.getSSOType() == SSOFlow.AUTHORIZATION_CODE) {
            // Check if we received an Authorization code.
            ResponseType responseType = successResponse.impliedResponseType();
            if (responseType.impliesImplicitFlow()) {
                ErrorObject errorObject = new ErrorObject("OCT-SSO-CLIENT-013", "Missing Authorization code");
                showErrorMessage(httpServletResponse, errorObject);
                return;
            }

            AuthorizationCode authorizationCode = successResponse.getAuthorizationCode();

            showDebugInfo(authorizationCode.getValue());

            try {
                URI redirectURI = new URI(variableClientData.getRootURL() + "/octopus/sso/SSOCallback");
                AuthorizationCodeGrant grant = new AuthorizationCodeGrant(authorizationCode, redirectURI);
                URI tokenEndPoint = new URI(config.getTokenEndpoint());
                // TODO Configurable
                ClientAuthentication clientAuth = new ClientSecretJWT(new ClientID(config.getSSOClientId())
                        , tokenEndPoint, JWSAlgorithm.HS512, new Secret(config.getSSOClientSecret()));

                TokenRequest tokenRequest = new TokenRequest(tokenEndPoint, clientAuth, grant, null);

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
            } catch (JOSEException e) {
                e.printStackTrace();
            }
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

    private AuthenticationResponse verifyRequestStructural(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, OpenIdVariableClientData variableClientData) {
        ErrorObject errorObject = null;

        if (variableClientData == null) {
            errorObject = new ErrorObject("OCT-SSO-CLIENT-012", "Request did not originate from this session");
            showErrorMessage(httpServletResponse, errorObject);
            return null;

        }
        String query = httpServletRequest.getQueryString();
        AuthenticationResponse authenticationResponse = null;
        State receivedState;
        try {
            URI responseURL = new URI("?" + query);

            authenticationResponse = AuthenticationResponseParser.parse(responseURL);
        } catch (URISyntaxException e) {
            errorObject = new ErrorObject("OCT-SSO-CLIENT-001", e.getMessage());
        } catch (ParseException e) {
            errorObject = new ErrorObject("OCT-SSO-CLIENT-002", e.getMessage());
        }

        if (authenticationResponse instanceof AuthenticationErrorResponse) {
            AuthenticationErrorResponse errorResponse = (AuthenticationErrorResponse) authenticationResponse;
            errorObject = errorResponse.getErrorObject();
            receivedState = errorResponse.getState();
        } else {
            if (authenticationResponse == null) {
                receivedState = findStateFromParameters(query);
            } else {
                receivedState = authenticationResponse.getState();
            }
        }

        if (errorObject == null) {
            errorObject = checkState(variableClientData, receivedState);
        }

        if (errorObject != null) {
            showErrorMessage(httpServletResponse, errorObject);
            return null;
        }
        return authenticationResponse;
    }

    private void showErrorMessage(HttpServletResponse httpServletResponse, ErrorObject errorObject) {
        try {
            httpServletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            httpServletResponse.getWriter().println(errorObject.getCode() + " : " + errorObject.getDescription());
        } catch (IOException e) {
            throw new OctopusUnexpectedException(e);
        }

    }

    private State findStateFromParameters(String query) {
        State result = null;
        Map<String, String> params = URLUtils.parseParameters(query);
        if (params.containsKey("state")) {
            result = State.parse(params.get("state"));
        }
        return result;
    }

    private ErrorObject checkState(OpenIdVariableClientData variableClientData, State state) {
        ErrorObject result = null;

        if (!variableClientData.getState().equals(state)) {
            result = new ErrorObject("OCT-SSO-CLIENT-011", "Request has an invalid 'state' value");
        }
        return result;

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

}
