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
package be.c4j.ee.security.credentials.authentication.jwt.client;

import be.c4j.ee.security.credentials.authentication.jwt.client.config.SCSClientConfig;
import be.c4j.ee.security.jwt.JWKManager;
import be.c4j.ee.security.jwt.config.JWTOperation;
import be.c4j.ee.security.jwt.config.MappingSystemAccountToApiKey;
import be.c4j.ee.security.util.TimeUtil;
import be.c4j.test.util.ReflectionUtil;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class JWTSystemTokenTest {


    private static final String API_KEY = "APIKey";
    private static final String SYSTEM_ACCOUNT = "systemAccount";
    private static final String SERVER = "JUnit";

    @Mock
    private SCSClientConfig SCSClientConfigMock;

    @Mock
    private JWKManager jwkManagerMock;

    @Mock
    private MappingSystemAccountToApiKey mappingSystemAccountToApiKeyMock;

    @InjectMocks
    private JWTSystemToken jwtSystemToken;

    @Before
    public void setup() throws IllegalAccessException {

        ReflectionUtil.injectDependencies(jwtSystemToken, new TimeUtil());
    }

    @Test
    public void createJWTSystemToken() throws ParseException, JOSEException {

        when(SCSClientConfigMock.getJWTOperation()).thenReturn(JWTOperation.JWT);
        jwtSystemToken.init();

        when(SCSClientConfigMock.getJWTTimeToLive()).thenReturn(2);
        when(SCSClientConfigMock.getServerName()).thenReturn(SERVER);
        RSAKey rsaJWK = makeRSA(2018, KeyUse.SIGNATURE, new Algorithm("PS512"), API_KEY);
        when(jwkManagerMock.getJWKForApiKey(API_KEY)).thenReturn(rsaJWK);

        when(mappingSystemAccountToApiKeyMock.getApiKey(SYSTEM_ACCOUNT)).thenReturn(API_KEY);

        String token = this.jwtSystemToken.createJWTSystemToken(SYSTEM_ACCOUNT);

        SignedJWT signedJWT = SignedJWT.parse(token);

        // Create verifier using the RSA key
        JWSVerifier verifier = new RSASSAVerifier(rsaJWK.toPublicJWK());

        assertThat(signedJWT.verify(verifier)).isTrue();

        // Ok, token is not tampered with.

        assertThat(signedJWT.getHeader().getKeyID()).isEqualTo(API_KEY); // KeyId (apiKey) is in the header

        assertThat(signedJWT.getJWTClaimsSet().getSubject()).isEqualTo(SYSTEM_ACCOUNT); // SystemAccount == Subject

        assertThat(signedJWT.getJWTClaimsSet().getAudience()).containsExactly(SERVER);

        assertThat(signedJWT.getJWTClaimsSet().getExpirationTime()).isAfter(new Date());

    }

    // TODO Other tests !! (expiration, encryption, ...)

    private RSAKey makeRSA(Integer keySize, KeyUse keyUse, Algorithm keyAlg, String kid) {

        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(keySize);
            KeyPair kp = generator.generateKeyPair();

            RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
            RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();

            return new RSAKey.Builder(pub)
                    .privateKey(priv)
                    .keyUse(keyUse)
                    .algorithm(keyAlg)
                    .keyID(kid)
                    .build();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }
}