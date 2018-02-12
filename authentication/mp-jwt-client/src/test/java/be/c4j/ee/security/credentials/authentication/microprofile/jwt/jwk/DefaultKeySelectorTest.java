/*
 * Copyright 2014-2018 Rudy De Busscher
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
package be.c4j.ee.security.credentials.authentication.microprofile.jwt.jwk;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.jwt.JWKManager;
import be.c4j.test.util.BeanManagerFake;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static com.nimbusds.jose.jwk.ECKey.Builder;
import static com.nimbusds.jose.jwk.ECKey.Curve;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class DefaultKeySelectorTest {

    private static final String SPECIAL_ID = "specialId";
    private static RSAKey rsaKey;

    private static ECKey ecKey;

    @Mock
    private JWKManager jwkManagerMock;

    private BeanManagerFake beanManagerFake;

    private DefaultKeySelector keySelector;

    @BeforeClass
    public static void createKeys() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        defineRSAKeyTest();
        defineECKeyTest();

    }

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();
        beanManagerFake.registerBean(jwkManagerMock, JWKManager.class);
        beanManagerFake.endRegistration();

        keySelector = new DefaultKeySelector();

    }

    @After
    public void cleanup() {
        beanManagerFake.deregistration();
    }

    @Test
    public void selectSecretKey_noKeyId_SingleKey() {
        when(jwkManagerMock.hasSingleKey()).thenReturn(true);
        when(jwkManagerMock.getSingleKey()).thenReturn(rsaKey);

        RSAKey rsaKey = keySelector.selectSecretKey(null, null);
        assertThat(rsaKey).isNotNull();
        assertThat(rsaKey.getKeyID()).isEqualTo("JUnit");

        verify(jwkManagerMock).hasSingleKey();
        verify(jwkManagerMock).getSingleKey();
    }

    @Test(expected = OctopusConfigurationException.class)
    public void selectSecretKey_noKeyId_WrongSingleKey() {
        when(jwkManagerMock.hasSingleKey()).thenReturn(true);
        when(jwkManagerMock.getSingleKey()).thenReturn(ecKey);

        try {
            keySelector.selectSecretKey(null, null);

        } finally {

            verify(jwkManagerMock).hasSingleKey();
            verify(jwkManagerMock).getSingleKey();
        }
    }

    @Test
    public void selectSecretKey_noKeyId_multipleKeys() {
        when(jwkManagerMock.hasSingleKey()).thenReturn(false);

        RSAKey rsaKey = keySelector.selectSecretKey(null, null);
        assertThat(rsaKey).isNull();

        verify(jwkManagerMock).hasSingleKey();
        verify(jwkManagerMock, never()).getSingleKey();
    }

    @Test
    public void selectSecretKey_knownKey() {
        when(jwkManagerMock.existsApiKey(SPECIAL_ID)).thenReturn(true);
        when(jwkManagerMock.getJWKForApiKey(SPECIAL_ID)).thenReturn(rsaKey);

        RSAKey rsaKey = keySelector.selectSecretKey(SPECIAL_ID, null);
        assertThat(rsaKey).isNotNull();
        assertThat(rsaKey.getKeyID()).isEqualTo("JUnit");  // Special test case where keyId of Key doesn't match the requested :)

        verify(jwkManagerMock).existsApiKey(SPECIAL_ID);
        verify(jwkManagerMock).getJWKForApiKey(SPECIAL_ID);
        verify(jwkManagerMock, never()).hasSingleKey();
        verify(jwkManagerMock, never()).getSingleKey();
    }

    @Test(expected = OctopusConfigurationException.class)
    public void selectSecretKey_knownKey_WrongType() {
        when(jwkManagerMock.existsApiKey(SPECIAL_ID)).thenReturn(true);
        when(jwkManagerMock.getJWKForApiKey(SPECIAL_ID)).thenReturn(ecKey);

        try {
            keySelector.selectSecretKey(SPECIAL_ID, null);
        } finally {
            verify(jwkManagerMock).existsApiKey(SPECIAL_ID);
            verify(jwkManagerMock).getJWKForApiKey(SPECIAL_ID);
            verify(jwkManagerMock, never()).hasSingleKey();
            verify(jwkManagerMock, never()).getSingleKey();
        }
    }

    @Test
    public void selectSecretKey_unknownKey_singleKey() {
        when(jwkManagerMock.existsApiKey(SPECIAL_ID)).thenReturn(false);
        when(jwkManagerMock.hasSingleKey()).thenReturn(true);
        when(jwkManagerMock.getSingleKey()).thenReturn(rsaKey);

        RSAKey rsaKey = keySelector.selectSecretKey(SPECIAL_ID, null);
        assertThat(rsaKey).isNotNull();
        assertThat(rsaKey.getKeyID()).isEqualTo("JUnit");

        // FIXME Test on the logger

        verify(jwkManagerMock).existsApiKey(SPECIAL_ID);
        verify(jwkManagerMock).hasSingleKey();
        verify(jwkManagerMock).getSingleKey();
        verify(jwkManagerMock, never()).getJWKForApiKey(SPECIAL_ID);
    }

    @Test(expected = OctopusConfigurationException.class)
    public void selectSecretKey_unknownKey_singleKey_WrongType() {
        when(jwkManagerMock.existsApiKey(SPECIAL_ID)).thenReturn(false);
        when(jwkManagerMock.hasSingleKey()).thenReturn(true);
        when(jwkManagerMock.getSingleKey()).thenReturn(ecKey);

        try {
            keySelector.selectSecretKey(SPECIAL_ID, null);
        } finally {

            verify(jwkManagerMock).existsApiKey(SPECIAL_ID);
            verify(jwkManagerMock).hasSingleKey();
            verify(jwkManagerMock).getSingleKey();
            verify(jwkManagerMock, never()).getJWKForApiKey(SPECIAL_ID);
        }
    }

    @Test
    public void selectSecretKey_unknownKey_multiplKey() {
        when(jwkManagerMock.existsApiKey(SPECIAL_ID)).thenReturn(false);
        when(jwkManagerMock.hasSingleKey()).thenReturn(false);

        RSAKey rsaKey = keySelector.selectSecretKey(SPECIAL_ID, null);
        assertThat(rsaKey).isNull();

        verify(jwkManagerMock).existsApiKey(SPECIAL_ID);
        verify(jwkManagerMock).hasSingleKey();
        verify(jwkManagerMock, never()).getSingleKey();
        verify(jwkManagerMock, never()).getJWKForApiKey(SPECIAL_ID);
    }

    private static void defineECKeyTest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");

        Curve curve = Curve.P_521;
        generator.initialize(curve.toECParameterSpec());
        KeyPair keyPair = generator.generateKeyPair();

        ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

        ecKey = new Builder(curve, pub)
                .privateKey(priv)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(new Algorithm("ES512"))
                .keyID("JUnit EC") // Give the key some ID (optional)
                .build();

    }

    private static void defineRSAKeyTest() throws NoSuchAlgorithmException {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair kp = generator.generateKeyPair();

        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
        RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();

        rsaKey = new RSAKey.Builder(pub)
                .privateKey(priv)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(new Algorithm("PS512"))
                .keyID("JUnit")
                .build();
    }


}