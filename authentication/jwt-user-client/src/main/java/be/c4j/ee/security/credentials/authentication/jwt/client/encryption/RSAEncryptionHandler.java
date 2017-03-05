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

import be.c4j.ee.security.credentials.authentication.jwt.client.config.JWTClientConfig;
import be.c4j.ee.security.jwt.config.JWKFileReader;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

/**
 *
 */

public class RSAEncryptionHandler implements EncryptionHandler {


    private JWTClientConfig jwtClientConfig;
    private JWKFileReader jwkFileReader;

    @Override
    public void init(JWTClientConfig jwtClientConfig, JWKFileReader jwkFileReader) {

        this.jwtClientConfig = jwtClientConfig;
        this.jwkFileReader = jwkFileReader;
    }

    @Override
    public String doEncryption(String apiKey, SignedJWT signedJWT) throws JOSEException {
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A256CBC_HS512)
                        .contentType("JWT") // required to signal nested JWT
                        .build(),
                new Payload(signedJWT));

        // Perform encryption
        JWK jwk = jwkFileReader.readJWKFile(apiKey, jwtClientConfig.getJWKFile());
        jweObject.encrypt(new RSAEncrypter((RSAKey) jwk));

        // Serialise to JWE compact form
        return jweObject.serialize();
    }
}
