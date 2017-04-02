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
import be.c4j.ee.security.sso.server.SSOProducerBean;
import be.c4j.ee.security.sso.server.client.ClientInfo;
import be.c4j.ee.security.sso.server.client.ClientInfoRetriever;
import be.c4j.ee.security.sso.server.config.SSOServerConfiguration;
import be.c4j.ee.security.sso.server.servlet.helper.OIDCTokenHelper;
import be.c4j.ee.security.sso.server.store.OIDCStoreData;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.minidev.json.JSONObject;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
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
@WebServlet("/octopus/sso/token")
public class TokenServlet extends HttpServlet {

    private Logger logger = LoggerFactory.getLogger(TokenServlet.class);

    @Inject
    private SSOProducerBean ssoProducerBean;

    @Inject
    private SSOServerConfiguration ssoServerConfiguration;

    @Inject
    private SSOTokenStore tokenStore;

    @Inject
    private OIDCTokenHelper oidcTokenHelper;

    @Inject
    private ClientInfoRetriever clientInfoRetriever;

    @Inject
    private OctopusConfig octopusConfig;

    @Override
    protected void doPost(HttpServletRequest httpServletRequest, HttpServletResponse response) throws ServletException, IOException {

        TokenRequest tokenRequest = (TokenRequest) httpServletRequest.getAttribute(AbstractRequest.class.getName());

        TokenResponse tokenResponse = null;
        AuthorizationGrant grant = tokenRequest.getAuthorizationGrant();

        try {

            if (grant instanceof AuthorizationCodeGrant) {
                tokenResponse = getResponseAuthorizationGrant(response, tokenRequest, (AuthorizationCodeGrant) grant);
            }

            if (grant instanceof ResourceOwnerPasswordCredentialsGrant) {
                tokenResponse = getResponsePasswordGrant(httpServletRequest, response, tokenRequest, (ResourceOwnerPasswordCredentialsGrant) grant);
            }

            if (tokenResponse != null) {
                response.setContentType("application/json");

                if (!tokenResponse.indicatesSuccess()) {
                    // TODO Check if it is always an 400 when an TokenErrorResponse.
                    // OK for ResourceOwnerPasswordCredentialsGrant when invalid PW is supplied
                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                }
                JSONObject jsonObject = tokenResponse.toHTTPResponse().getContentAsJSONObject();
                response.getWriter().append(jsonObject.toJSONString());
            }
        } catch (Exception e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new OctopusUnexpectedException(e);
        }
    }

    private TokenResponse getResponsePasswordGrant(HttpServletRequest httpServletRequest, HttpServletResponse response, TokenRequest tokenRequest, ResourceOwnerPasswordCredentialsGrant grant) {

        TokenResponse result;

        UsernamePasswordToken token = new UsernamePasswordToken(grant.getUsername(), grant.getPassword().getValue());

        try {
            // FIXME Other SE clients to check
            SecurityUtils.getSubject().login(token);

            result = createTokensForPasswordGrant(httpServletRequest, tokenRequest);
        } catch (AuthenticationException e) {
            // OAuth2 (RFC 6749) 5.2.  Error Response
            ErrorObject errorObject = new ErrorObject("unauthorized_client", "ResourceOwnerPasswordCredentialsGrant is not allowed for client_id");
            return new TokenErrorResponse(errorObject);
        } catch (ParseException e) {
            throw new OctopusUnexpectedException(e);
        }

        return result;
    }

    private TokenResponse createTokensForPasswordGrant(HttpServletRequest httpServletRequest, TokenRequest tokenRequest) throws ParseException {

        IDTokenClaimsSet claimsSet = null;

        OIDCStoreData oidcStoreData = new OIDCStoreData(new BearerAccessToken(ssoServerConfiguration.getOIDCTokenLength()
                , ssoServerConfiguration.getSSOAccessTokenTimeToLive(), tokenRequest.getScope()));

        OctopusSSOUser ssoUser = ssoProducerBean.getOctopusSSOUser();
        ;
        if (tokenRequest.getScope() != null && tokenRequest.getScope().contains("openid")) {
            // TODO Study spec to see if these can be combined and it makes sense to do so?

            ClientID clientID = tokenRequest.getClientAuthentication().getClientID();
            // openid scope requires clientId
            claimsSet = oidcTokenHelper.defineIDToken(httpServletRequest, ssoUser, clientID);

            oidcStoreData.setClientId(clientID);
        }

        if (oidcStoreData.getClientId() != null) {
            ClientInfo clientInfo = clientInfoRetriever.retrieveInfo(oidcStoreData.getClientId().getValue());
            if (!clientInfo.isDirectAccessAllowed()) {
                ErrorObject errorObject = new ErrorObject("unauthorized_client", "ResourceOwnerPasswordCredentialsGrant is not allowed for client_id");
                return new TokenErrorResponse(errorObject);
            }
        }
        oidcStoreData.setIdTokenClaimsSet(claimsSet);

        oidcStoreData.setScope(tokenRequest.getScope());

        String userAgent = httpServletRequest.getHeader("User-Agent");
        String remoteHost = httpServletRequest.getRemoteAddr();

        // FIXME verify that ssoUser.getCookieToken() == null
        tokenStore.addLoginFromClient(ssoUser, null, userAgent, remoteHost, oidcStoreData);

        return defineResponse(oidcStoreData);
    }

    private AccessTokenResponse getResponseAuthorizationGrant(HttpServletResponse response, TokenRequest tokenRequest, AuthorizationCodeGrant codeGrant) throws ParseException {

        OIDCStoreData oidcStoreData = tokenStore.getOIDCDataByAuthorizationCode(codeGrant.getAuthorizationCode(), tokenRequest.getClientAuthentication().getClientID());
        if (oidcStoreData == null) {
            showErrorMessage(response, InvalidClientException.EXPIRED_SECRET);
            return null;
        }

        return defineResponse(oidcStoreData);
    }

    private void showErrorMessage(HttpServletResponse response, InvalidClientException expiredSecret) {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        TokenErrorResponse tokenErrorResponse = new TokenErrorResponse(expiredSecret.getErrorObject());
        try {
            response.getWriter().println(tokenErrorResponse.toJSONObject().toJSONString());
        } catch (IOException e) {
            throw new OctopusUnexpectedException(e);
        }

    }

    private AccessTokenResponse defineResponse(OIDCStoreData oidcStoreData) throws ParseException {
        AccessTokenResponse result;

        if (oidcStoreData.getIdTokenClaimsSet() != null) {
            // FIXME Config
            PlainJWT plainJWT = new PlainJWT(oidcStoreData.getIdTokenClaimsSet().toJWTClaimsSet());

            OIDCTokens token = new OIDCTokens(plainJWT, oidcStoreData.getAccessToken(), null); // TODO refresh tokens
            result = new OIDCTokenResponse(token);
        } else {
            Tokens token = new Tokens(oidcStoreData.getAccessToken(), null); // TODO refresh tokens
            result = new AccessTokenResponse(token);
        }

        return result;

    }

    private void showDebugInfo(OctopusSSOUser user) {
        // FIXME Correct logging
        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("User %s is authenticated and cookie written if needed.", user.getFullName()));
        }
    }
}
