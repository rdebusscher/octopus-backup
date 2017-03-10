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
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.server.OIDCErrorMessage;
import be.c4j.ee.security.sso.server.SSOProducerBean;
import be.c4j.ee.security.sso.server.client.ClientInfo;
import be.c4j.ee.security.sso.server.client.ClientInfoRetriever;
import be.c4j.ee.security.sso.server.config.SSOServerConfiguration;
import be.c4j.ee.security.sso.server.store.OIDCStoreData;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;
import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.List;

/**
 *
 */
@WebServlet("/octopus/sso/authenticate")
public class AuthenticationServlet extends HttpServlet {

    private Logger logger = LoggerFactory.getLogger(AuthenticationServlet.class);

    @Inject
    private SSOServerConfiguration ssoServerConfiguration;

    @Inject
    private SSOProducerBean ssoProducerBean;

    @Inject
    private SSOTokenStore tokenStore;

    @Inject
    private ClientInfoRetriever clientInfoRetriever;

    @Inject
    private OctopusConfig octopusConfig;

    @Override
    public void init() throws ServletException {
        super.init();
    }

    @Override
    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse response) throws ServletException, IOException {
        // We can't inject the OctopusSSOUSer because we then get a Proxy which is stored.
        // Bad things will happen ....
        OctopusSSOUser ssoUser = ssoProducerBean.getOctopusSSOUser();

        AuthenticationRequest request = (AuthenticationRequest) httpServletRequest.getAttribute(AbstractRequest.class.getName());

        AuthenticationErrorResponse errorResponse = null;

        // FIXME Move these checks to the OIDCFilter
        String clientId = request.getClientID().getValue();
        ClientInfo clientInfo = clientInfoRetriever.retrieveInfo(clientId);

        if (clientInfo == null) {
            errorResponse = defineError(request, OIDCErrorMessage.AUTHENTICATE_UNKNOWN_CLIENT_ID);
        }

        if (errorResponse == null) {

            URI redirectURI = request.getRedirectionURI();
            if (!clientInfo.getCallbackURL().equals(redirectURI.toString())
                    && !((clientInfo.getCallbackURL() + "/octopus/sso/SSOCallback").equals(redirectURI.toString()))) {
                errorResponse = defineError(request, OIDCErrorMessage.AUTHENTICATE_UNKNOWN_REDIRECT_URI);
            }
        }


        AuthenticationSuccessResponse successResponse = null;
        if (errorResponse == null) {
            AuthorizationCode authorizationCode = null;
            AccessToken accessToken = null;

            IDTokenClaimsSet claimsSet = defineIDToken(httpServletRequest, ssoUser, request, clientId);

            OIDCStoreData oidcStoreData = new OIDCStoreData();
            oidcStoreData.setIdTokenClaimsSet(claimsSet);

            if (request.getResponseType().impliesCodeFlow()) {
                authorizationCode = new AuthorizationCode();
                oidcStoreData.setAuthorizationCode(authorizationCode);  // FIXME length from config

                // implicit -> onmiddelijk idToken
                // code flow -> fist code, then exchanged to accessToken/idToken
            } else {
                accessToken = ssoUser.getBearerAccessToken();
            }

            tokenStore.addLoginFromClient(ssoUser, clientId, oidcStoreData);

            State state = request.getState();

            successResponse = new AuthenticationSuccessResponse(request.getRedirectionURI(), authorizationCode, null, accessToken, state, null, ResponseMode.QUERY);

        }

        try {
            if (errorResponse != null) {
                errorResponse.toHTTPRequest().send();
            } else {
                String callback = successResponse.toURI().toString();

                showDebugInfo(ssoUser);
                response.sendRedirect(callback);

                //SecurityUtils.getSubject().logout();// Do not use logout of subject, it wil remove the cookie which we need !
            }
        } catch (IOException e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new OctopusUnexpectedException(e);

        } finally {
            httpServletRequest.getSession().invalidate();  // Don't keep the session on the SSO server
        }
    }

    private IDTokenClaimsSet defineIDToken(HttpServletRequest httpServletRequest, OctopusSSOUser ssoUser, AuthenticationRequest request, String clientId) {
        Nonce nonce = request.getNonce();

        Issuer iss = new Issuer(determineRoot(httpServletRequest));
        Subject sub = new Subject(ssoUser.getName());
        List<Audience> audList = new Audience(clientId).toSingleAudienceList();
        Date exp = new Date();
        Date iat = new Date(1000L);

        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(iss, sub, audList, exp, iat);

        claimsSet.setNonce(nonce);
        return claimsSet;
    }

    private AuthenticationErrorResponse defineError(AuthenticationRequest request, OIDCErrorMessage errorMessage) {
        ErrorObject errorObject = new ErrorObject(errorMessage.getCode(), errorMessage.getMessage());
        return new AuthenticationErrorResponse(request.getRedirectionURI(), errorObject, request.getState(), request.getResponseMode());

    }

    private void showDebugInfo(OctopusSSOUser user) {
        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("User %s is authenticated and cookie written if needed.", user.getFullName()));
        }
    }

    protected String determineRoot(HttpServletRequest req) {
        // FIXME Duplicate with OAuth2ServiceProducer
        StringBuilder result = new StringBuilder();
        result.append(req.getScheme()).append("://");
        result.append(req.getServerName()).append(':');
        result.append(req.getServerPort());
        result.append(req.getContextPath());
        return result.toString();
    }
}
