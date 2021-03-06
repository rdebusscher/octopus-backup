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
package be.c4j.ee.security.sso.client;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import com.nimbusds.jose.JWSAlgorithm;
import org.junit.Test;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class JWSAlgorithmFactoryTest {

    private JWSAlgorithmFactory factory = new JWSAlgorithmFactory();

    @Test
    public void determineOptimalAlgorithm_secretShort() {

        JWSAlgorithm algorithm = factory.determineOptimalAlgorithm(defineSecret(256 / 8 + 1));

        assertThat(algorithm).isEqualTo(JWSAlgorithm.HS256);
    }

    @Test
    public void determineOptimalAlgorithm_secretMedium() {

        JWSAlgorithm algorithm = factory.determineOptimalAlgorithm(defineSecret(384 / 8 + 1));

        assertThat(algorithm).isEqualTo(JWSAlgorithm.HS384);
    }

    @Test
    public void determineOptimalAlgorithm_secretLong() {

        JWSAlgorithm algorithm = factory.determineOptimalAlgorithm(defineSecret(512 / 8 + 1));

        assertThat(algorithm).isEqualTo(JWSAlgorithm.HS512);
    }

    @Test(expected = OctopusConfigurationException.class)
    public void determineOptimalAlgorithm_TooShort() {

        factory.determineOptimalAlgorithm(defineSecret(184 / 8 + 1));

    }


    private byte[] defineSecret(int byteLength) {
        byte[] bytes = new byte[byteLength];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(bytes);

        return bytes;
    }

}