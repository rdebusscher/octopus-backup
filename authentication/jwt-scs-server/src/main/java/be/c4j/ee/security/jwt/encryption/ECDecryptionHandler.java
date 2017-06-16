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
package be.c4j.ee.security.jwt.encryption;

import be.c4j.ee.security.jwt.JWKManager;
import be.c4j.ee.security.jwt.config.SCSConfig;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;

/**
 *
 */

public class ECDecryptionHandler implements DecryptionHandler {

    private JWKManager jwkManager;

    @Override
    public void init(SCSConfig SCSConfig, JWKManager jwkManager) {

        this.jwkManager = jwkManager;
    }

    @Override
    public SignedJWT doDecryption(String apiKey, String token) throws ParseException, JOSEException {
        JWEObject jweObject = JWEObject.parse(token);

        // Decrypt with private EC key

        // TODO Check if the key exists
        JWK jwk = jwkManager.getJWKForApiKey(apiKey);

        jweObject.decrypt(new ECDHDecrypter((ECKey) jwk));

        // Extract payload
        return jweObject.getPayload().toSignedJWT();

    }


}
