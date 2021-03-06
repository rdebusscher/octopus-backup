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
import be.c4j.ee.security.authentication.octopus.exception.OctopusRetrievalException;
import be.c4j.ee.security.config.Debug;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.sso.client.JWSAlgorithmFactory;
import be.c4j.ee.security.sso.client.OpenIdVariableClientData;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
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
import java.nio.charset.Charset;

/**
 *
 */
@ApplicationScoped
public class ExchangeForAccessCode {

    private Logger logger = LoggerFactory.getLogger(SSOCallbackServlet.class);

    @Inject
    private OctopusConfig octopusConfig;

    @Inject
    private OctopusSEConfiguration config;

    @Inject
    private JWSAlgorithmFactory jwsAlgorithmFactory;

    @Inject
    private CallbackErrorHandler callbackErrorHandler;

    private JWSAlgorithm algorithm;

    @PostConstruct
    public void init() {
        algorithm = jwsAlgorithmFactory.determineOptimalAlgorithm(config.getSSOClientSecret());
    }

    public BearerAccessToken doExchange(HttpServletResponse httpServletResponse, OpenIdVariableClientData variableClientData, AuthorizationCode authorizationCode) {
        BearerAccessToken result = null;

        showDebugInfo(authorizationCode.getValue());

        try {
            URI redirectURI = new URI(variableClientData.getRootURL() + "/octopus/sso/SSOCallback");
            AuthorizationCodeGrant grant = new AuthorizationCodeGrant(authorizationCode, redirectURI);
            URI tokenEndPoint = new URI(config.getTokenEndpoint());

            ClientAuthentication clientAuth = new ClientSecretJWT(new ClientID(config.getSSOClientId())
                    , tokenEndPoint, algorithm, new Secret(new String(config.getSSOClientSecret(), Charset.forName("UTF-8"))));

            TokenRequest tokenRequest = new TokenRequest(tokenEndPoint, clientAuth, grant, null);

            HTTPResponse response = tokenRequest.toHTTPRequest().send();
            TokenResponse tokenResponse = OIDCTokenResponseParser.parse(response);

            if (tokenResponse instanceof OIDCTokenResponse) {
                OIDCTokenResponse oidcResponse = (OIDCTokenResponse) tokenResponse;
                OIDCTokens oidcTokens = oidcResponse.getOIDCTokens();

                JWT idToken = oidcTokens.getIDToken();

                result = oidcTokens.getBearerAccessToken();

                verifyJWT(idToken);

                IDTokenClaimsVerifier claimsVerifier = new IDTokenClaimsVerifier(new Issuer(config.getOctopusSSOServer()), new ClientID(config.getSSOClientId()), variableClientData.getNonce(), 0);
                claimsVerifier.verify(idToken.getJWTClaimsSet(), null);
            } else {
                TokenErrorResponse errorResponse = (TokenErrorResponse) tokenResponse;
                ErrorObject errorObject = errorResponse.getErrorObject();
                if (errorObject.getCode() == null || errorObject.getDescription() == null) {
                    errorObject = errorObject.setDescription(errorObject.getDescription() + " -- TokenErrorResponse for authorization code " + authorizationCode);
                }

                callbackErrorHandler.showErrorMessage(httpServletResponse, errorObject);
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
            // thrown by new ClientSecretJWT
            result = null;

            ErrorObject errorObject = new ErrorObject("OCT-SSO-CLIENT-019", "HMAC calculation failed");
            callbackErrorHandler.showErrorMessage(httpServletResponse, errorObject);
        } catch (OctopusRetrievalException e) {
            result = null;

            callbackErrorHandler.showErrorMessage(httpServletResponse, e.getErrorObject());
        } catch (IOException e) {
            throw new OctopusUnexpectedException(e);
        }
        return result;
    }

    private void verifyJWT(JWT idToken) throws OctopusRetrievalException {
        // TODO If PlainJWT -> Reject!
        // According to OpenIdSpec it must be JWS or JWE, so plain isn't supported
        // But OctopusServer never generates one.
        // TODO What happens if we point octopus-client to another OpenIdConnect Server?
        if (idToken instanceof SignedJWT) {
            SignedJWT signedJWT = (SignedJWT) idToken;

            try {
                boolean valid = signedJWT.verify(new MACVerifier(config.getSSOIdTokenSecret()));
                if (!valid) {
                    ErrorObject errorObject = new ErrorObject("OCT-SSO-CLIENT-015", "JWT Signature Validation failed");
                    throw new OctopusRetrievalException(errorObject);

                }
            } catch (JOSEException e) {
                ErrorObject errorObject = new ErrorObject("OCT-SSO-CLIENT-015", "JWT Signature Validation failed");
                throw new OctopusRetrievalException(errorObject);
            }

        }
    }

    private void showDebugInfo(String token) {

        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("(SSO Client) Call SSO Server for User info (token = %s)", token));
        }

    }
}
