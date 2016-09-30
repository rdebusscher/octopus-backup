/*
 * Copyright 2014-2016 Rudy De Busscher (www.c4j.be)
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
 *
 */
package be.c4j.ee.security.credentials.authentication.keycloak;

import org.keycloak.RSATokenVerifier;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OIDCAuthenticationError;
import org.keycloak.common.VerificationException;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 */
public class AccessTokenHandler {

    private static final Logger logger = LoggerFactory.getLogger(AccessTokenHandler.class);

    private KeycloakDeployment deployment;
    private AccessTokenResponse accessTokenResponse;

    public AccessTokenHandler(KeycloakDeployment deployment, AccessTokenResponse accessTokenResponse) {
        this.deployment = deployment;
        this.accessTokenResponse = accessTokenResponse;
    }

    public KeycloakUser extractUser() {
        String idTokenString = accessTokenResponse.getIdToken();
        AccessToken accessToken;
        IDToken idToken = null;
        try {
            accessToken = RSATokenVerifier.verifyToken(accessTokenResponse.getToken(), deployment.getRealmKey(), deployment.getRealmInfoUrl());
            if (idTokenString != null) {
                try {
                    JWSInput input = new JWSInput(idTokenString);
                    idToken = input.readJsonContent(IDToken.class);
                } catch (JWSInputException e) {
                    throw new VerificationException();
                }
            }
            logger.debug("Token Verification succeeded!");
        } catch (VerificationException e) {
            logger.error("failed verification of token: " + e.getMessage());
            throw new OIDCAuthenticationException(OIDCAuthenticationError.Reason.INVALID_TOKEN);

        }

        if (accessTokenResponse.getNotBeforePolicy() > deployment.getNotBefore()) {
            deployment.setNotBefore(accessTokenResponse.getNotBeforePolicy());
        }
        if (accessToken.getIssuedAt() < deployment.getNotBefore()) {
            logger.error("Stale token");
            throw new OIDCAuthenticationException(OIDCAuthenticationError.Reason.STALE_TOKEN);

        }

        if (idToken == null) {
            throw new OIDCAuthenticationException(OIDCAuthenticationError.Reason.CODE_TO_TOKEN_FAILURE);
        }

        KeycloakUser user = KeycloakUser.fromIdToken(idToken);

        user.setAccessToken(accessTokenResponse);

        user.setClientSession(accessToken.getClientSession());

        // TODO Other parameters

        return user;

    }
}
