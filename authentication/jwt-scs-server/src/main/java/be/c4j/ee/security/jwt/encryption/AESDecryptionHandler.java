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

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.jwt.JWKManager;
import be.c4j.ee.security.jwt.config.SCSConfig;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;

/**
 *
 */

public class AESDecryptionHandler implements DecryptionHandler {

    private SCSConfig jwtServerConfig;

    @Override
    public void init(SCSConfig SCSConfig, JWKManager jwkManager) {

        this.jwtServerConfig = SCSConfig;
        // We don't need the jwkManager here
    }

    @Override
    public SignedJWT doDecryption(String apiKey, String token) throws ParseException, JOSEException {
        JWEObject jweObject = JWEObject.parse(token);

        // Decrypt with shared key
        String aesTokenSecret = jwtServerConfig.getAESTokenSecret();
        if (aesTokenSecret == null || aesTokenSecret.trim().isEmpty()) {
            throw new OctopusConfigurationException("Parameter jwt.aes.secret is required");
        }
        Base64 aesSecret = new Base64(aesTokenSecret);

        jweObject.decrypt(new AESDecrypter(aesSecret.decode()));

        // Extract payload
        return jweObject.getPayload().toSignedJWT();

    }


}
