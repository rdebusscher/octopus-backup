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
package be.c4j.ee.security.credentials.authentication.mp.filter;

import be.c4j.ee.security.credentials.authentication.mp.keys.JWKManagerKeySelector;
import be.c4j.ee.security.credentials.authentication.mp.keys.TestKeys;
import be.c4j.test.util.ReflectionUtil;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.shiro.authc.AuthenticationException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import uk.org.lidalia.slf4jext.Level;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import java.text.ParseException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class MPBearerTokenHandlerTest {

    @Mock
    private JWKManagerKeySelector keySelectorMock;

    @Mock
    private MPBearerTokenVerifier tokenVerifierMock;

    @InjectMocks
    private MPBearerTokenHandler tokenHandler;

    private TestLogger logger;

    @Before
    public void setup() throws IllegalAccessException {
        logger = TestLoggerFactory.getTestLogger(MPBearerTokenHandler.class);
        ReflectionUtil.injectDependencies(tokenHandler, logger);
    }

    @After
    public void clearLoggers() {
        TestLoggerFactory.clear();

    }

    @Test
    public void processToken() throws JOSEException, ParseException {
        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(new JWSAlgorithm("RS256"));
        headerBuilder.keyID("kid");
        SignedJWT signedJWT = new SignedJWT(headerBuilder.build(), new JWTClaimsSet.Builder().build());

        RSAKey rsaKey = TestKeys.makeRSA(2018, KeyUse.SIGNATURE, new Algorithm("PS512"), "kid");
        JWSSigner signer = new RSASSASigner(rsaKey);
        signedJWT.sign(signer);

        when(keySelectorMock.selectSecretKey("kid")).thenReturn(rsaKey.toRSAPublicKey());
        when(tokenVerifierMock.verify(any(JWSHeader.class))).thenReturn(true);
        when(tokenVerifierMock.verify(any(JWTClaimsSet.class))).thenReturn(true);

        SignedJWT jwt = tokenHandler.processToken(signedJWT.serialize());
        assertThat(jwt).isNotNull();
        assertThat(jwt.getHeader().toJSONObject().toString()).isEqualTo("{\"kid\":\"kid\",\"alg\":\"RS256\"}");
        assertThat(jwt.getJWTClaimsSet().toJSONObject().toString()).isEqualTo("{}");

    }

    @Test(expected = AuthenticationException.class)
    public void processToken_wrongAlgorithm() throws JOSEException, ParseException {

        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(new JWSAlgorithm("HS256"));
        SignedJWT signedJWT = new SignedJWT(headerBuilder.build(), new JWTClaimsSet.Builder().build());

        RSAKey rsaKey = TestKeys.makeRSA(2018, KeyUse.SIGNATURE, new Algorithm("PS512"), "kid");
        JWSSigner signer = new MACSigner("justForTestingjustForTestingjustForTesting");
        signedJWT.sign(signer);

        // Actually, the wrong header is just determined by the verify method here. So we need to return false here
        when(tokenVerifierMock.verify(any(JWSHeader.class))).thenReturn(false);

        try {
            tokenHandler.processToken(signedJWT.serialize());
        } finally {

            verify(tokenVerifierMock, never()).verify(any(JWTClaimsSet.class));
            assertThat(logger.getLoggingEvents()).hasSize(1);
            assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.ERROR);
            assertThat(logger.getLoggingEvents().get(0).getMessage()).startsWith("MicroProfile JWT Auth Token Error : token not valid ey");

        }

    }

    @Test(expected = AuthenticationException.class)
    public void processToken_missingKid() throws JOSEException, ParseException {
        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(new JWSAlgorithm("RS256"));
        SignedJWT signedJWT = new SignedJWT(headerBuilder.build(), new JWTClaimsSet.Builder().build());

        RSAKey rsaKey = TestKeys.makeRSA(2018, KeyUse.SIGNATURE, new Algorithm("PS512"), "kid");
        JWSSigner signer = new RSASSASigner(rsaKey);
        signedJWT.sign(signer);

        when(tokenVerifierMock.verify(any(JWSHeader.class))).thenReturn(true);

        try {
            tokenHandler.processToken(signedJWT.serialize());
        } finally {

            verify(tokenVerifierMock, never()).verify(any(JWTClaimsSet.class));

            assertThat(logger.getLoggingEvents()).hasSize(1);
            assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.ERROR);
            assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("MicroProfile JWT Auth Token Error : Unknown kid null");

        }

    }

    @Test(expected = AuthenticationException.class)
    public void processToken_WrongKey() throws JOSEException, ParseException {
        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(new JWSAlgorithm("RS256"));
        headerBuilder.keyID("kid");
        SignedJWT signedJWT = new SignedJWT(headerBuilder.build(), new JWTClaimsSet.Builder().build());

        RSAKey wrongRsaKey = TestKeys.makeRSA(2018, KeyUse.SIGNATURE, new Algorithm("PS512"), "kid");
        JWSSigner signer = new RSASSASigner(wrongRsaKey);
        signedJWT.sign(signer);

        RSAKey rsaKey = TestKeys.makeRSA(2018, KeyUse.SIGNATURE, new Algorithm("PS512"), "kid");
        when(keySelectorMock.selectSecretKey("kid")).thenReturn(rsaKey.toRSAPublicKey());

        when(tokenVerifierMock.verify(any(JWSHeader.class))).thenReturn(true);

        try {
            SignedJWT jwt = tokenHandler.processToken(signedJWT.serialize());
        } finally {
            verify(tokenVerifierMock, never()).verify(any(JWTClaimsSet.class));

            assertThat(logger.getLoggingEvents()).hasSize(1);
            assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.ERROR);
            assertThat(logger.getLoggingEvents().get(0).getMessage()).startsWith("MicroProfile JWT Auth Token Error : token not valid ");

        }
    }

    @Test(expected = AuthenticationException.class)
    public void processToken_changedPayload() throws JOSEException, ParseException {
        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(new JWSAlgorithm("RS256"));
        headerBuilder.keyID("kid");
        SignedJWT signedJWT = new SignedJWT(headerBuilder.build(), new JWTClaimsSet.Builder().build());

        RSAKey rsaKey = TestKeys.makeRSA(2018, KeyUse.SIGNATURE, new Algorithm("PS512"), "kid");
        JWSSigner signer = new RSASSASigner(rsaKey);
        signedJWT.sign(signer);

        String[] correctToken = signedJWT.serialize().split("\\.");

        signedJWT = new SignedJWT(headerBuilder.build(), new JWTClaimsSet.Builder().issuer("JUnit").build());
        signedJWT.sign(signer);
        String[] otherToken = signedJWT.serialize().split("\\.");

        when(keySelectorMock.selectSecretKey("kid")).thenReturn(rsaKey.toRSAPublicKey());
        when(tokenVerifierMock.verify(any(JWSHeader.class))).thenReturn(true);

        try {
            SignedJWT jwt = tokenHandler.processToken(correctToken[0] + "." + otherToken[1] + "." + correctToken[2]);
        } finally {
            verify(tokenVerifierMock, never()).verify(any(JWTClaimsSet.class));

            assertThat(logger.getLoggingEvents()).hasSize(1);
            assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.ERROR);
            assertThat(logger.getLoggingEvents().get(0).getMessage()).startsWith("MicroProfile JWT Auth Token Error : token not valid ");

        }

    }

    @Test(expected = AuthenticationException.class)
    public void processToken_verificationFailed() throws JOSEException, ParseException {
        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(new JWSAlgorithm("RS256"));
        headerBuilder.keyID("kid");
        SignedJWT signedJWT = new SignedJWT(headerBuilder.build(), new JWTClaimsSet.Builder().build());

        RSAKey rsaKey = TestKeys.makeRSA(2018, KeyUse.SIGNATURE, new Algorithm("PS512"), "kid");
        JWSSigner signer = new RSASSASigner(rsaKey);
        signedJWT.sign(signer);

        when(keySelectorMock.selectSecretKey("kid")).thenReturn(rsaKey.toRSAPublicKey());
        when(tokenVerifierMock.verify(any(JWSHeader.class))).thenReturn(true);
        when(tokenVerifierMock.verify(any(JWTClaimsSet.class))).thenReturn(false);

        try {
            SignedJWT jwt = tokenHandler.processToken(signedJWT.serialize());
        } finally {
            assertThat(logger.getLoggingEvents()).hasSize(1);
            assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.ERROR);
            assertThat(logger.getLoggingEvents().get(0).getMessage()).startsWith("MicroProfile JWT Auth Token Error : token not valid ");

        }

    }

    @Test(expected = AuthenticationException.class)
    public void processToken_wrongtokenCharacters() throws JOSEException, ParseException {

        try {
            SignedJWT jwt = tokenHandler.processToken("ThisIsNotAValidToken");
        } finally {
            assertThat(logger.getLoggingEvents()).hasSize(1);
            assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.ERROR);
            assertThat(logger.getLoggingEvents().get(0).getMessage()).startsWith("MicroProfile JWT Auth Token Error : token not valid ");

        }

    }

}