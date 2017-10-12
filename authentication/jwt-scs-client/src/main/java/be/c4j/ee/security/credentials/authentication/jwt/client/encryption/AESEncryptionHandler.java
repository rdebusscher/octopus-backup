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
import be.c4j.ee.security.util.StringUtil;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;
import org.apache.deltaspike.core.api.provider.BeanProvider;

/**
 *
 */

public class AESEncryptionHandler implements EncryptionHandler {


    private SCSConfig scsConfig;

    private StringUtil stringUtil;

    @Override
    public void init(SCSConfig SCSConfig, JWKManager jwkManager) {

        this.scsConfig = SCSConfig;
        // We don't need the jwkManager for AES

        stringUtil = BeanProvider.getContextualReference(StringUtil.class);
    }

    @Override
    public String doEncryption(String apiKey, SignedJWT signedJWT) throws JOSEException {
        // Create JWE object with signed JWT as payload
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.A256KW, EncryptionMethod.A256CBC_HS512)
                        .contentType("JWT") // required to signal nested JWT
                        .build(),
                new Payload(signedJWT));

        // Perform encryption
        String aesTokenSecret = scsConfig.getAESTokenSecret();
        if (stringUtil.isEmpty(aesTokenSecret)) {
            throw new OctopusConfigurationException("Parameter jwt.aes.secret is required");
        }
        Base64 aesSecret = new Base64(aesTokenSecret);
        jweObject.encrypt(new AESEncrypter(aesSecret.decode()));

        // Serialise to JWE compact form
        return jweObject.serialize();
    }
}
