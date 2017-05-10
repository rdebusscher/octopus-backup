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

import be.c4j.ee.security.jwt.config.JWEAlgorithm;
import be.c4j.ee.security.jwt.config.JWKFileReader;
import be.c4j.ee.security.jwt.config.JWTUserConfig;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class DecryptionHandlerFactory {

    @Inject
    private JWTUserConfig jwtServerConfig;

    @Inject
    private JWKFileReader jwkFileReader;

    private Map<JWEAlgorithm, DecryptionHandler> handlerInstances = new HashMap<JWEAlgorithm, DecryptionHandler>();

    public DecryptionHandler getDecryptionHandler(JWEAlgorithm jweAlgorithm) {
        DecryptionHandler result;
        switch (jweAlgorithm) {

            case AES:
                result = handlerInstances.get(jweAlgorithm);
                if (result == null) {
                    result = new AESDecryptionHandler();
                    result.init(jwtServerConfig, jwkFileReader);
                    handlerInstances.put(jweAlgorithm, result);
                }
                break;
            case EC:
                result = handlerInstances.get(jweAlgorithm);
                if (result == null) {
                    result = new ECDecryptionHandler();
                    result.init(jwtServerConfig, jwkFileReader);
                    handlerInstances.put(jweAlgorithm, result);
                }
                break;
            case RSA:
                result = handlerInstances.get(jweAlgorithm);
                if (result == null) {
                    result = new RSADecryptionHandler();
                    result.init(jwtServerConfig, jwkFileReader);
                    handlerInstances.put(jweAlgorithm, result);
                }
                break;
            default:
                throw new IllegalArgumentException("Value " + jweAlgorithm + " not supported");
        }
        return result;

    }


}
