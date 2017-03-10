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
package be.c4j.ee.security.jwt.config;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.test.TestConfigSource;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.junit.After;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class JWTUserConfigTest {

    private JWTUserConfig jwtUserConfig = new JWTUserConfig();

    @After
    public void teardown() {
        ConfigResolver.freeConfigSources();
    }

    @Test
    public void getJWTOperation_JWT() {
        Map<String, String> values = new HashMap<String, String>();
        values.put("jwt.algorithms", "HS256");
        TestConfigSource.defineConfigValue(values);
        JWTOperation jwtOperation = jwtUserConfig.getJWTOperation();
        assertThat(jwtOperation).isEqualTo(JWTOperation.JWT);

        JWTSignature jwtSignature = jwtUserConfig.getJwtSignature();
        assertThat(jwtSignature).isEqualTo(JWTSignature.HS256);
    }

    @Test
    public void getJWTOperation_JWT_NotSpecified() {
        // On the JWT User Server side, the JWT Signature doesn't need to be specified as it is contained in the JWT Header of the Token
        Map<String, String> values = new HashMap<String, String>();
        TestConfigSource.defineConfigValue(values);

        JWTOperation jwtOperation = jwtUserConfig.getJWTOperation();
        assertThat(jwtOperation).isEqualTo(JWTOperation.JWT);

        JWTSignature jwtSignature = jwtUserConfig.getJwtSignature();
        assertThat(jwtSignature).isNull();
    }

    @Test
    public void getJWTOperation_JWT_InvalidValue() {
        Map<String, String> values = new HashMap<String, String>();
        values.put("jwt.algorithms", "JUnit");
        TestConfigSource.defineConfigValue(values);
        JWTOperation jwtOperation = jwtUserConfig.getJWTOperation();
        assertThat(jwtOperation).isEqualTo(JWTOperation.JWT);

        JWTSignature jwtSignature = jwtUserConfig.getJwtSignature();
        assertThat(jwtSignature).isNull();
    }

    @Test
    public void getJWTOperation_JWE_AES() {
        Map<String, String> values = new HashMap<String, String>();
        values.put("jwt.algorithms", "HS256 AES");
        values.put("jwt.aes.secret", "123");
        TestConfigSource.defineConfigValue(values);

        JWTOperation jwtOperation = jwtUserConfig.getJWTOperation();
        assertThat(jwtOperation).isEqualTo(JWTOperation.JWE);

        JWTSignature jwtSignature = jwtUserConfig.getJwtSignature();
        assertThat(jwtSignature).isEqualTo(JWTSignature.HS256);

        JWEAlgorithm jweAlgorithm = jwtUserConfig.getJWEAlgorithm();
        assertThat(jweAlgorithm).isEqualTo(JWEAlgorithm.AES);
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getJWTOperation_JWE_AES_MissingSecret() {
        Map<String, String> values = new HashMap<String, String>();
        values.put("jwt.algorithms", "HS256 AES");
        TestConfigSource.defineConfigValue(values);

        jwtUserConfig.getJWTOperation();
    }

    @Test
    public void getJWTOperation_JWE_EC() {
        Map<String, String> values = new HashMap<String, String>();
        values.put("jwt.algorithms", "HS384 EC");
        values.put("jwk.file", "private.jwk");
        TestConfigSource.defineConfigValue(values);

        JWTOperation jwtOperation = jwtUserConfig.getJWTOperation();
        assertThat(jwtOperation).isEqualTo(JWTOperation.JWE);

        JWTSignature jwtSignature = jwtUserConfig.getJwtSignature();
        assertThat(jwtSignature).isEqualTo(JWTSignature.HS384);

        JWEAlgorithm jweAlgorithm = jwtUserConfig.getJWEAlgorithm();
        assertThat(jweAlgorithm).isEqualTo(JWEAlgorithm.EC);
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getJWTOperation_JWE_EC_MissingFile() {
        Map<String, String> values = new HashMap<String, String>();
        values.put("jwt.algorithms", "HS256 EC");
        TestConfigSource.defineConfigValue(values);

        jwtUserConfig.getJWTOperation();
    }

    @Test
    public void getJWTOperation_JWE_RSA() {
        Map<String, String> values = new HashMap<String, String>();
        values.put("jwt.algorithms", "HS512 RSA");
        values.put("jwk.file", "private.jwk");
        TestConfigSource.defineConfigValue(values);

        JWTOperation jwtOperation = jwtUserConfig.getJWTOperation();
        assertThat(jwtOperation).isEqualTo(JWTOperation.JWE);

        JWTSignature jwtSignature = jwtUserConfig.getJwtSignature();
        assertThat(jwtSignature).isEqualTo(JWTSignature.HS512);

        JWEAlgorithm jweAlgorithm = jwtUserConfig.getJWEAlgorithm();
        assertThat(jweAlgorithm).isEqualTo(JWEAlgorithm.RSA);
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getJWTOperation_JWE_RSA_MissingFile() {
        Map<String, String> values = new HashMap<String, String>();
        values.put("jwt.algorithms", "HS256 RSA");
        TestConfigSource.defineConfigValue(values);

        jwtUserConfig.getJWTOperation();
    }

    @Test
    public void getHMACTokenSecret() {
        Map<String, String> values = new HashMap<String, String>();
        values.put("jwt.hmac.secret", "secret");
        TestConfigSource.defineConfigValue(values);

        String tokenSecret = jwtUserConfig.getHMACTokenSecret();
        assertThat(tokenSecret).isNotNull();
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getHMACTokenSecret_MissingValue() {
        jwtUserConfig.getHMACTokenSecret();
    }

}