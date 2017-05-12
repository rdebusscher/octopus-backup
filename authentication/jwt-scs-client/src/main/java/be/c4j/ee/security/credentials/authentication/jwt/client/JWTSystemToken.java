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
package be.c4j.ee.security.credentials.authentication.jwt.client;

import be.c4j.ee.security.credentials.authentication.jwt.client.config.SCSClientConfig;
import be.c4j.ee.security.credentials.authentication.jwt.client.encryption.EncryptionHandler;
import be.c4j.ee.security.credentials.authentication.jwt.client.encryption.EncryptionHandlerFactory;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.jwt.JWKManager;
import be.c4j.ee.security.jwt.config.JWTOperation;
import be.c4j.ee.security.jwt.config.MappingSystemAccountToApiKey;
import be.c4j.ee.security.util.TimeUtil;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.Date;

/**
 *
 */
@ApplicationScoped
public class JWTSystemToken {

    @Inject
    private SCSClientConfig SCSClientConfig;

    @Inject
    private JWKManager jwkManager;

    @Inject
    private MappingSystemAccountToApiKey mappingSystemAccountToApiKey;

    @Inject
    private EncryptionHandlerFactory encryptionHandlerFactory;

    @Inject
    private TimeUtil timeUtil;

    private JWTOperation jwtOperation;

    @PostConstruct
    public void init() {
        jwtOperation = SCSClientConfig.getJWTOperation();

    }

    public String createJWTSystemToken(String systemAccount) {

        String apiKey = mappingSystemAccountToApiKey.getApiKey(systemAccount);
        if (apiKey == null || apiKey.isEmpty()) {
            throw new OctopusConfigurationException(String.format("No api-key found in the jwt.systemaccounts.map for '%s'", systemAccount));
        }

        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder();
        claimsSetBuilder.subject(systemAccount);
        claimsSetBuilder.audience(SCSClientConfig.getServerName());

        Date issueTime = new Date();
        claimsSetBuilder.issueTime(issueTime);

        claimsSetBuilder.expirationTime(timeUtil.addSecondsToDate(SCSClientConfig.getJWTTimeToLive(), issueTime));
        // TODO Extension to add custom claims. Is this needed ?
        //claimsSetBuilder.claim("clientAddress", "127.0.0.1");

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS512).type(JOSEObjectType.JWT).keyID(apiKey).build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSetBuilder.build());

        // Apply the Signing protection

        try {
            JWSSigner signer = new RSASSASigner((RSAKey) jwkManager.getJWKForApiKey(apiKey));

            signedJWT.sign(signer);

        } catch (JOSEException e) {
            throw new OctopusUnexpectedException(e);
        }

        String result;
        if (jwtOperation == JWTOperation.JWE) {
            result = encryptToken(apiKey, signedJWT);
        } else {
            result = signedJWT.serialize();
        }
        return result;

    }

    private String encryptToken(String apiKey, SignedJWT signedJWT) {
        String result;
        try {
            EncryptionHandler encryptionHandler = encryptionHandlerFactory.getEncryptionHandler(SCSClientConfig.getJWEAlgorithm());
            result = encryptionHandler.doEncryption(apiKey, signedJWT);
        } catch (JOSEException e) {
            throw new OctopusUnexpectedException(e);
        }
        return result;
    }

}

