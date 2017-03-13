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
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.server.SSOProducerBean;
import be.c4j.ee.security.sso.server.client.ClientInfo;
import be.c4j.ee.security.sso.server.client.ClientInfoRetriever;
import be.c4j.ee.security.sso.server.config.SSOServerConfiguration;
import be.c4j.ee.security.sso.server.store.OIDCStoreData;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;
import be.c4j.ee.security.util.TimeUtil;
import be.c4j.ee.security.util.URLUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
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

    @Inject
    private URLUtil urlUtil;

    @Inject
    private TimeUtil timeUtil;

    @Override
    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse response) throws ServletException, IOException {
        // We can't inject the OctopusSSOUSer because we then get a Proxy which is stored.
        // Bad things will happen ....
        OctopusSSOUser ssoUser = ssoProducerBean.getOctopusSSOUser();

        AuthenticationRequest request = (AuthenticationRequest) httpServletRequest.getAttribute(AbstractRequest.class.getName());

        if (ssoUser.getBearerAccessToken() == null) {
            ssoUser.setBearerAccessToken(new BearerAccessToken(ssoServerConfiguration.getOIDCTokenLength()));
        }

        String clientId = request.getClientID().getValue();
        IDTokenClaimsSet claimsSet = defineIDToken(httpServletRequest, ssoUser, request, clientId);

        OIDCStoreData oidcStoreData = new OIDCStoreData();

        AuthorizationCode authorizationCode = null;
        AccessToken accessToken = null;

        SignedJWT idToken = null;

        if (request.getResponseType().impliesCodeFlow()) {
            authorizationCode = new AuthorizationCode(ssoServerConfiguration.getOIDCTokenLength());
            oidcStoreData.setAuthorizationCode(authorizationCode);

            // implicit -> idToken immediately transferred
            // code flow -> first code, then exchanged to accessToken/idToken
        } else {
            if (request.getResponseType().contains("token")) {
                // Set the variable so that the Access code is send in this response.
                accessToken = ssoUser.getBearerAccessToken();
            }
            try {

                ClientInfo clientInfo = clientInfoRetriever.retrieveInfo(clientId);

                idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet.toJWTClaimsSet());

                idToken.sign(new MACSigner(clientInfo.getIdtokenSecret()));
            } catch (ParseException e) {
                throw new OctopusUnexpectedException(e);
            } catch (KeyLengthException e) {
                throw new OctopusConfigurationException(e.getMessage());  // TODO Better informative message
                // Although, developers should take care that no invalid value can be stored (and thus retrieved here)
            } catch (JOSEException e) {
                throw new OctopusUnexpectedException(e);
            }
        }

        // Access code must be set in all situations so that it is available later on.
        oidcStoreData.setAccessCode(ssoUser.getBearerAccessToken());

        oidcStoreData.setIdTokenClaimsSet(claimsSet);

        oidcStoreData.setClientId(request.getClientID());
        oidcStoreData.setScope(request.getScope());

        String userAgent = httpServletRequest.getHeader("User-Agent");
        String remoteHost = httpServletRequest.getRemoteAddr();

        tokenStore.addLoginFromClient(ssoUser, ssoUser.getCookieToken(), userAgent, remoteHost, oidcStoreData);

        State state = request.getState();

        AuthenticationSuccessResponse successResponse = new AuthenticationSuccessResponse(request.getRedirectionURI()
                , authorizationCode, idToken, accessToken, state, null, ResponseMode.QUERY);

        try {
            String callback = successResponse.toURI().toString();

            showDebugInfo(ssoUser);
            response.sendRedirect(callback);

            //SecurityUtils.getSubject().logout();// Do not use logout of subject, it wil remove the cookie which we need !
        } catch (IOException e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new OctopusUnexpectedException(e);

        } finally {
            httpServletRequest.getSession().invalidate();  // Don't keep the session on the SSO server
        }
    }

    private IDTokenClaimsSet defineIDToken(HttpServletRequest httpServletRequest, OctopusSSOUser ssoUser, AuthenticationRequest request, String clientId) {
        Nonce nonce = request.getNonce();

        Issuer iss = new Issuer(urlUtil.determineRoot(httpServletRequest));
        Subject sub = new Subject(ssoUser.getName());
        List<Audience> audList = new Audience(clientId).toSingleAudienceList();
        Date iat = new Date();
        Date exp = timeUtil.addSecondsToDate(60, iat); // TODO Verify how we handle expiration when multiple clients are using the server

        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(iss, sub, audList, exp, iat);

        claimsSet.setNonce(nonce);
        return claimsSet;
    }

    private void showDebugInfo(OctopusSSOUser user) {
        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("User %s is authenticated and cookie written if needed.", user.getFullName()));
        }
    }

}
