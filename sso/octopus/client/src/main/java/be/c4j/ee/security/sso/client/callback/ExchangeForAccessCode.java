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
import be.c4j.ee.security.sso.client.OpenIdVariableClientData;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.nimbusds.openid.connect.sdk.validators.IDTokenClaimsVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;

/**
 *
 */
@ApplicationScoped
public class ExchangeForAccessCode {

    private Logger logger = LoggerFactory.getLogger(SSOCallbackServlet.class);

    @Inject
    private OctopusConfig octopusConfig;

    @Inject
    private OctopusSSOClientConfiguration config;

    @Inject
    private CallbackErrorHandler callbackErrorHandler;

    private JWSAlgorithm algorithm;

    @PostConstruct
    public void init() {
        Set<JWSAlgorithm> algorithms = MACSigner.getCompatibleAlgorithms(ByteUtils.bitLength(config.getSSOClientSecret()));

        if (algorithms.contains(JWSAlgorithm.HS512)) {
            algorithm = JWSAlgorithm.HS512;
        }
        if (algorithm == null && algorithms.contains(JWSAlgorithm.HS384)) {
            algorithm = JWSAlgorithm.HS384;
        }
        if (algorithm == null && algorithms.contains(JWSAlgorithm.HS256)) {
            algorithm = JWSAlgorithm.HS256;
        }
    }

    public BearerAccessToken doExchange(HttpServletResponse httpServletResponse, OpenIdVariableClientData variableClientData, AuthorizationCode authorizationCode) {
        BearerAccessToken result = null;

        showDebugInfo(authorizationCode.getValue());

        try {
            URI redirectURI = new URI(variableClientData.getRootURL() + "/octopus/sso/SSOCallback");
            AuthorizationCodeGrant grant = new AuthorizationCodeGrant(authorizationCode, redirectURI);
            URI tokenEndPoint = new URI(config.getTokenEndpoint());


            ClientAuthentication clientAuth = new ClientSecretJWT(new ClientID(config.getSSOClientId())
                    , tokenEndPoint, algorithm, new Secret(new String(config.getSSOClientSecret())));  // TODO Verify the UTF encoding

            TokenRequest tokenRequest = new TokenRequest(tokenEndPoint, clientAuth, grant, null);

            HTTPResponse response = tokenRequest.toHTTPRequest().send();
            TokenResponse tokenResponse = OIDCTokenResponseParser.parse(response);

            if (tokenResponse instanceof OIDCTokenResponse) {
                OIDCTokenResponse oidcResponse = (OIDCTokenResponse) tokenResponse;
                OIDCTokens oidcTokens = oidcResponse.getOIDCTokens();

                JWT idToken = oidcTokens.getIDToken();

                result = oidcTokens.getBearerAccessToken();

                IDTokenClaimsVerifier claimsVerifier = new IDTokenClaimsVerifier(new Issuer(config.getSSOServer()), new ClientID(config.getSSOClientId()), variableClientData.getNonce(), 0);
                claimsVerifier.verify(idToken.getJWTClaimsSet());
            } else {
                TokenErrorResponse errorResponse = (TokenErrorResponse) tokenResponse;
                callbackErrorHandler.showErrorMessage(httpServletResponse, errorResponse.getErrorObject());
            }

        } catch (URISyntaxException e) {
            throw new OctopusUnexpectedException(e);

        } catch (ParseException e) {
            result = null;

            ErrorObject errorObject = new ErrorObject("OCT-SSO-CLIENT-018", "Parsing of Token endpoint response failed : " + e.getMessage());
            callbackErrorHandler.showErrorMessage(httpServletResponse, errorObject);

        } catch (java.text.ParseException e) {
            result = null;

            ErrorObject errorObject = new ErrorObject("OCT-SSO-CLIENT-017", "Parsing of ID Token failed : " + e.getMessage());
            callbackErrorHandler.showErrorMessage(httpServletResponse, errorObject);

        } catch (BadJWTException e) {
            result = null;

            ErrorObject errorObject = new ErrorObject("OCT-SSO-CLIENT-016", "Validation of ID token JWT failed : " + e.getMessage());
            callbackErrorHandler.showErrorMessage(httpServletResponse, errorObject);
        } catch (JOSEException e) {
            result = null;

            ErrorObject errorObject = new ErrorObject("OCT-SSO-CLIENT-015", "HMAC calculation failed");
            callbackErrorHandler.showErrorMessage(httpServletResponse, errorObject);
        } catch (IOException e) {
            throw new OctopusUnexpectedException(e);
        }
        return result;
    }

    private void showDebugInfo(String token) {

        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("Call SSO Server for User info (token = %s)", token));
        }

    }
}
