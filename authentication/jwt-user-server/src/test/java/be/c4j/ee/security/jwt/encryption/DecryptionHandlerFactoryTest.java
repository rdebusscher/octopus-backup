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
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Describe in this block the functionality of the class.
 * Created by rubus on 05/03/17.
 */

public class DecryptionHandlerFactoryTest {

    @Test
    public void getDecryptionHandler_AES() {

        DecryptionHandlerFactory factory = new DecryptionHandlerFactory();

        DecryptionHandler handler = factory.getDecryptionHandler(JWEAlgorithm.AES);
        assertThat(handler).isInstanceOf(AESDecryptionHandler.class);
    }

    @Test
    public void getDecryptionHandler_AES_cached() {

        DecryptionHandlerFactory factory = new DecryptionHandlerFactory();

        DecryptionHandler handler1 = factory.getDecryptionHandler(JWEAlgorithm.AES);
        DecryptionHandler handler2 = factory.getDecryptionHandler(JWEAlgorithm.AES);

        assertThat(handler1).isSameAs(handler2);

    }

    @Test
    public void getDecryptionHandler_EC() {

        DecryptionHandlerFactory factory = new DecryptionHandlerFactory();

        DecryptionHandler handler = factory.getDecryptionHandler(JWEAlgorithm.EC);
        assertThat(handler).isInstanceOf(ECDecryptionHandler.class);
    }

    @Test
    public void getDecryptionHandler_EC_cached() {

        DecryptionHandlerFactory factory = new DecryptionHandlerFactory();

        DecryptionHandler handler1 = factory.getDecryptionHandler(JWEAlgorithm.EC);
        DecryptionHandler handler2 = factory.getDecryptionHandler(JWEAlgorithm.EC);

        assertThat(handler1).isSameAs(handler2);

    }

    @Test
    public void getDecryptionHandler_RSA() {

        DecryptionHandlerFactory factory = new DecryptionHandlerFactory();

        DecryptionHandler handler = factory.getDecryptionHandler(JWEAlgorithm.RSA);
        assertThat(handler).isInstanceOf(RSADecryptionHandler.class);
    }

    @Test
    public void getDecryptionHandler_RSA_cached() {

        DecryptionHandlerFactory factory = new DecryptionHandlerFactory();

        DecryptionHandler handler1 = factory.getDecryptionHandler(JWEAlgorithm.RSA);
        DecryptionHandler handler2 = factory.getDecryptionHandler(JWEAlgorithm.RSA);

        assertThat(handler1).isSameAs(handler2);

    }

}