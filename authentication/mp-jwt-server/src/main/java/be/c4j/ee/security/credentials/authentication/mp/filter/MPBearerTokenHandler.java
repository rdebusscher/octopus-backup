/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.c4j.ee.security.credentials.authentication.mp.filter;

import be.c4j.ee.security.credentials.authentication.mp.keys.JWKManagerKeySelector;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.apache.shiro.authc.AuthenticationException;
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

/**
 * Parses and verifies (signing and claims) a JWT serialized token.
 */
@ApplicationScoped
public class MPBearerTokenHandler {

    @Inject
    private Logger logger;

    @Inject
    private JWKManagerKeySelector keySelector;

    @Inject
    private MPBearerTokenVerifier tokenVerifier;

    public SignedJWT processToken(String token) {
        try {
            // Parse token
            SignedJWT signedJWT = SignedJWT.parse(token);

            JWSHeader header = signedJWT.getHeader();
            if (!tokenVerifier.verify(header)) {
                logger.error(String.format("MicroProfile JWT Auth Token Error : token not valid %s", token));
                throw new AuthenticationException("Invalid MicroProfile JWT Auth token");
            }

            JWSVerifier verifier;
            RSAPublicKey publicKey = (RSAPublicKey) keySelector.selectSecretKey(header.getKeyID());
            if (publicKey == null) {
                logger.error(String.format("MicroProfile JWT Auth Token Error : Unknown kid %s", header.getKeyID()));
                throw new AuthenticationException("Invalid MicroProfile JWT Auth token");
            }
            verifier = new RSASSAVerifier(publicKey);

            if (signedJWT.verify(verifier) && tokenVerifier.verify( signedJWT.getJWTClaimsSet())) {
                return signedJWT;

            } else {
                logger.error(String.format("MicroProfile JWT Auth Token Error : token not valid %s", token));
                throw new AuthenticationException("Invalid MicroProfile JWT Auth token");
            }
        } catch (ParseException e) {
            logger.error(String.format("MicroProfile JWT Auth Token Error : token not valid %s", token));
            throw new AuthenticationException("Invalid MicroProfile JWT Auth token");
        } catch (JOSEException e) {
            logger.error(String.format("MicroProfile JWT Auth Token Error : token not valid %s", token));
            throw new AuthenticationException("Invalid MicroProfile JWT Auth token");
        }

    }
}
