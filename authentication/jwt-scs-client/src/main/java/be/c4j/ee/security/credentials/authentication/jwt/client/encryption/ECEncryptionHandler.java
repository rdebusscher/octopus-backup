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
package be.c4j.ee.security.credentials.authentication.jwt.client.encryption;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.jwt.JWKManager;
import be.c4j.ee.security.jwt.config.SCSConfig;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;

/**
 *
 */

public class ECEncryptionHandler implements EncryptionHandler {


    private JWKManager jwkManager;

    @Override
    public void init(SCSConfig SCSConfig, JWKManager jwkManager) {

        this.jwkManager = jwkManager;
    }

    @Override
    public String doEncryption(String apiKey, SignedJWT signedJWT) throws JOSEException {
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256CBC_HS512)
                        .contentType("JWT") // required to signal nested JWT
                        .build(),
                new Payload(signedJWT));

        // Perform encryption
        String apiKeyEncryption = apiKey + "_enc";
        JWK jwk = jwkManager.getJWKForApiKey(apiKeyEncryption);  // TODO Document. We can't use the KeyUse, since JwkSet just finds the first key with loking up a key by id
        if (jwk == null) {
            // TODO This is not the correct response. Someone with an arbitrary api key can generate a stacktrace
            throw new OctopusConfigurationException(String.format("No RSA key found for %s", apiKeyEncryption));
        }

        jweObject.encrypt(new ECDHEncrypter((ECKey) jwk));

        // Serialise to JWE compact form
        return jweObject.serialize();
    }
}
