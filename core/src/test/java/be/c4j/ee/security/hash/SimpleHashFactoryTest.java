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
package be.c4j.ee.security.hash;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class SimpleHashFactoryTest extends AbstractKeyNameTest {

    private SimpleHashFactory factory;

    @Before
    public void setup() {
        factory = SimpleHashFactory.getInstance();
    }

    @Test
    public void defineRealHashAlgorithmName_forHashName() {
        String algorithmName = factory.defineRealHashAlgorithmName("SHA-256");
        assertThat(algorithmName).isEqualTo("SHA-256");
    }

    @Test
    public void defineRealHashAlgorithmName_forKeyName() {
        String algorithmName = factory.defineRealHashAlgorithmName("PBKDF2");

        String expected = defineExpectedName();
        assertThat(algorithmName).isEqualTo(expected);
    }

    @Test(expected = OctopusConfigurationException.class)
    public void defineRealHashAlgorithmName_other() {
        factory.defineRealHashAlgorithmName("other");
    }

    @Test
    public void defineHash_forHashName() {
        factory.defineRealHashAlgorithmName("SHA-256"); // required to correctly initialize factory
        SimpleHash hash = factory.defineHash("SHA-256", "password", "salt", 1);
        assertThat(hash).isExactlyInstanceOf(SimpleHash.class);
        assertThat(hash.toHex()).isEqualTo("13601bda4ea78e55a07b98866d2be6be0744e3866f13c00c811cab608a28f322");

    }

    @Test
    public void defineHash_forKeyName() {
        factory.defineRealHashAlgorithmName("PBKDF2"); // required to correctly initialize factory
        SimpleHash hash = factory.defineHash("PBKDF2", "password", "salt", 1);
        assertThat(hash).isExactlyInstanceOf(SecretKeyHash.class);
        assertThat(hash.toHex()).isEqualTo("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    }

}