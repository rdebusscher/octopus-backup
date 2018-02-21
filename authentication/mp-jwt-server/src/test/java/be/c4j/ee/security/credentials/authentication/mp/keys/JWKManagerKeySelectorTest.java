/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.c4j.ee.security.credentials.authentication.mp.keys;

import be.c4j.ee.security.jwt.JWKManager;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.*;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.security.Key;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class JWKManagerKeySelectorTest {

    private static final String SOME_KEY = "some.key";
    private static RSAKey rsaKey;
    private static ECKey ecKey;
    private static OctetSequenceKey octetSequenceKey;

    @Mock
    private JWKManager jwkManagerMock;

    @Mock
    private JWK jwkMock;

    @BeforeClass
    public static void setup() {
        rsaKey = TestKeys.makeRSA(2018, KeyUse.SIGNATURE, new Algorithm("PS512"), "kidRSA");
        ecKey = TestKeys.makeEC(new Algorithm("ES512"), KeyUse.SIGNATURE, ECKey.Curve.P_521, "kidEC");
        octetSequenceKey = TestKeys.makeHMAC();
    }

    @InjectMocks
    private JWKManagerKeySelector jwkManagerKeySelector;

    @Test
    public void selectSecretKey() {
        when(jwkManagerMock.existsApiKey(SOME_KEY)).thenReturn(Boolean.FALSE);
        Key key = jwkManagerKeySelector.selectSecretKey(SOME_KEY);
        assertThat(key).isNull();
    }

    @Test
    public void selectSecretKey_RSA() {
        when(jwkManagerMock.existsApiKey(SOME_KEY)).thenReturn(Boolean.TRUE);
        when(jwkManagerMock.getJWKForApiKey(SOME_KEY)).thenReturn(rsaKey);

        Key key = jwkManagerKeySelector.selectSecretKey(SOME_KEY);
        assertThat(key).isNotNull();

    }

    @Test
    public void selectSecretKey_EC() {
        when(jwkManagerMock.existsApiKey(SOME_KEY)).thenReturn(Boolean.TRUE);
        when(jwkManagerMock.getJWKForApiKey(SOME_KEY)).thenReturn(ecKey);

        Key key = jwkManagerKeySelector.selectSecretKey(SOME_KEY);
        assertThat(key).isNotNull();

    }

    @Test
    public void selectSecretKey_octet() {
        when(jwkManagerMock.existsApiKey(SOME_KEY)).thenReturn(Boolean.TRUE);
        when(jwkManagerMock.getJWKForApiKey(SOME_KEY)).thenReturn(octetSequenceKey);

        Key key = jwkManagerKeySelector.selectSecretKey(SOME_KEY);
        assertThat(key).isNotNull();

    }

    @Test(expected = UnsupportedOperationException.class)
    public void selectSecretKey_newTypeJWK() {
        when(jwkManagerMock.existsApiKey(SOME_KEY)).thenReturn(Boolean.TRUE);
        when(jwkManagerMock.getJWKForApiKey(SOME_KEY)).thenReturn(jwkMock);

        jwkManagerKeySelector.selectSecretKey(SOME_KEY);
    }

}