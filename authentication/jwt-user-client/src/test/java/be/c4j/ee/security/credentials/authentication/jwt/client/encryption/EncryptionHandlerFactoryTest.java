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

import be.c4j.ee.security.jwt.config.JWEAlgorithm;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class EncryptionHandlerFactoryTest {


    @Test
    public void getEncryptionHandler_AES() {
        EncryptionHandlerFactory factory = new EncryptionHandlerFactory();

        EncryptionHandler encryptionHandler = factory.getEncryptionHandler(JWEAlgorithm.AES);
        assertThat(encryptionHandler).isInstanceOf(AESEncryptionHandler.class);
    }

    @Test
    public void getEncryptionHandler_AES_cached() {
        EncryptionHandlerFactory factory = new EncryptionHandlerFactory();

        EncryptionHandler encryptionHandler1 = factory.getEncryptionHandler(JWEAlgorithm.AES);
        EncryptionHandler encryptionHandler2 = factory.getEncryptionHandler(JWEAlgorithm.AES);

        assertThat(encryptionHandler1).isSameAs(encryptionHandler2);

    }

    @Test
    public void getEncryptionHandler_EC() {
        EncryptionHandlerFactory factory = new EncryptionHandlerFactory();

        EncryptionHandler encryptionHandler = factory.getEncryptionHandler(JWEAlgorithm.EC);
        assertThat(encryptionHandler).isInstanceOf(ECEncryptionHandler.class);
    }

    @Test
    public void getEncryptionHandler_EC_cached() {
        EncryptionHandlerFactory factory = new EncryptionHandlerFactory();

        EncryptionHandler encryptionHandler1 = factory.getEncryptionHandler(JWEAlgorithm.EC);
        EncryptionHandler encryptionHandler2 = factory.getEncryptionHandler(JWEAlgorithm.EC);

        assertThat(encryptionHandler1).isSameAs(encryptionHandler2);

    }

    @Test
    public void getEncryptionHandler_RSA() {
        EncryptionHandlerFactory factory = new EncryptionHandlerFactory();

        EncryptionHandler encryptionHandler = factory.getEncryptionHandler(JWEAlgorithm.RSA);
        assertThat(encryptionHandler).isInstanceOf(RSAEncryptionHandler.class);
    }

    @Test
    public void getEncryptionHandler_RSA_cached() {
        EncryptionHandlerFactory factory = new EncryptionHandlerFactory();

        EncryptionHandler encryptionHandler1 = factory.getEncryptionHandler(JWEAlgorithm.RSA);
        EncryptionHandler encryptionHandler2 = factory.getEncryptionHandler(JWEAlgorithm.RSA);

        assertThat(encryptionHandler1).isSameAs(encryptionHandler2);

    }

}