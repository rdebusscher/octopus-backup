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

import be.c4j.ee.security.credentials.authentication.jwt.client.config.JWTClientConfig;
import be.c4j.ee.security.credentials.authentication.jwt.client.encryption.EncryptionHandler;
import be.c4j.ee.security.credentials.authentication.jwt.client.encryption.EncryptionHandlerFactory;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.jwt.config.JWEAlgorithm;
import be.c4j.ee.security.jwt.config.JWTOperation;
import be.c4j.ee.security.jwt.config.JWTSignature;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.realm.AuthorizationInfoBuilder;
import be.c4j.test.util.BeanManagerFake;
import be.c4j.util.ReflectionUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.codec.Base64;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.security.SecureRandom;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class JWTUserTokenTest {

    @Mock
    private JWTClientConfig jwtClientConfigMock;

    @Mock
    private JWTClaimsProvider jwtClaimsProviderMock;

    @Mock
    private EncryptionHandlerFactory encryptionHandlerFactoryMock;

    @Mock
    private EncryptionHandler encryptionHandlerMock;

    @InjectMocks
    private JWTUserToken jwtUserToken;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() {

        beanManagerFake = new BeanManagerFake();
        beanManagerFake.endRegistration();
    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void createJWTUserToken_happyCase() throws IllegalAccessException, ParseException {

        String secret = getHMACSecret();

        when(jwtClientConfigMock.getJwtSignature()).thenReturn(JWTSignature.HS256);
        when(jwtClientConfigMock.getHMACTokenSecret()).thenReturn(secret);

        jwtUserToken.init();

        UserPrincipal userPrincipal = new UserPrincipal("serialId", "JUnit", "Octopus");
        userPrincipal.getInfo().put(UserPrincipal.EXTERNAL_ID, "123");

        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();
        builder.addPermission("stringPermission");
        builder.addPermission(new NamedDomainPermission("namedPermission", "Test:*:*"));
        AuthorizationInfo info = builder.build();

        userPrincipal.addUserInfo("authorizationInfo", info);

        ReflectionUtil.injectDependencies(jwtUserToken, userPrincipal);

        String token = jwtUserToken.createJWTUserToken(null, null);
        assertThat(token).isNotNull();

        SignedJWT.parse(token);  // If token can be parsed, the it is A JWT and this is enough (JWT wise)

        String[] split = token.split("\\.");
        String payload = new String(Base64.decode(split[1]));
        assertThat(payload).startsWith("{\"sub\":\"{\\\"permissions\\\":[\\\"stringPermission\\\",\\\"test:*:*\\\"],\\\"roles\\\":[],\\\"name\\\":\\\"Octopus\\\",\\\"externalId\\\":\\\"123\\\",\\\"id\\\":\\\"serialId\\\",\\\"userName\\\":\\\"JUnit\\\"}\",\"exp\":");

    }

    @Test(expected = OctopusConfigurationException.class)
    public void createJWTUserToken_secretTooShort() throws IllegalAccessException, ParseException {

        when(jwtClientConfigMock.getHMACTokenSecret()).thenReturn(getHMACSecretShort());

        jwtUserToken.init();
    }

    @Test
    public void createJWTUserToken_happyCase_additionalClaims() throws IllegalAccessException, ParseException {

        String secret = getHMACSecret();

        when(jwtClientConfigMock.getJwtSignature()).thenReturn(JWTSignature.HS256);
        when(jwtClientConfigMock.getHMACTokenSecret()).thenReturn(secret);

        jwtUserToken.init();

        UserPrincipal userPrincipal = new UserPrincipal("serialId", "JUnit", "Octopus");
        userPrincipal.getInfo().put(UserPrincipal.EXTERNAL_ID, "123");

        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();
        builder.addPermission("stringPermission");
        builder.addPermission(new NamedDomainPermission("namedPermission", "Test:*:*"));
        AuthorizationInfo info = builder.build();

        userPrincipal.addUserInfo("authorizationInfo", info);

        ReflectionUtil.injectDependencies(jwtUserToken, userPrincipal);

        Map<String, Object> data = new HashMap<String, Object>();
        data.put("Key", "JUnit");
        when(jwtClaimsProviderMock.defineAdditionalClaims(userPrincipal)).thenReturn(data);

        String token = jwtUserToken.createJWTUserToken(null, jwtClaimsProviderMock);
        assertThat(token).isNotNull();

        SignedJWT.parse(token);  // If token can be parsed, the it is A JWT and this is enough (JWT wise)

        String[] split = token.split("\\.");
        String payload = new String(Base64.decode(split[1]));
        assertThat(payload).startsWith("{\"sub\":\"{\\\"permissions\\\":[\\\"stringPermission\\\",\\\"test:*:*\\\"],\\\"roles\\\":[],\\\"name\\\":\\\"Octopus\\\",\\\"externalId\\\":\\\"123\\\",\\\"id\\\":\\\"serialId\\\",\\\"userName\\\":\\\"JUnit\\\"}\",\"exp\":");

        assertThat(payload).contains("\"Key\":\"JUnit\"");

    }

    @Test
    public void createJWTUserToken_happyCase_encryption() throws IllegalAccessException, JOSEException {

        String secret = getHMACSecret();

        when(jwtClientConfigMock.getJWTOperation()).thenReturn(JWTOperation.JWE);
        when(jwtClientConfigMock.getJWEAlgorithm()).thenReturn(JWEAlgorithm.AES);

        when(jwtClientConfigMock.getJwtSignature()).thenReturn(JWTSignature.HS256);
        when(jwtClientConfigMock.getHMACTokenSecret()).thenReturn(secret);

        jwtUserToken.init();

        UserPrincipal userPrincipal = new UserPrincipal("serialId", "JUnit", "Octopus");
        userPrincipal.getInfo().put(UserPrincipal.EXTERNAL_ID, "123");

        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();
        builder.addPermission("stringPermission");
        builder.addPermission(new NamedDomainPermission("namedPermission", "Test:*:*"));
        AuthorizationInfo info = builder.build();

        when(encryptionHandlerFactoryMock.getEncryptionHandler(JWEAlgorithm.AES)).thenReturn(encryptionHandlerMock);
        when(encryptionHandlerMock.doEncryption((String) isNull(), any(SignedJWT.class))).thenReturn("The encrypted");
        userPrincipal.addUserInfo("authorizationInfo", info);

        ReflectionUtil.injectDependencies(jwtUserToken, userPrincipal);

        String token = jwtUserToken.createJWTUserToken(null, null);
        assertThat(token).isNotNull();

        assertThat(token).isEqualTo("The encrypted");

    }

    @Test(expected = OctopusUnexpectedException.class)
    public void createJWTUserToken_encryption_exception() throws IllegalAccessException, ParseException, JOSEException {

        String secret = getHMACSecret();

        when(jwtClientConfigMock.getJWTOperation()).thenReturn(JWTOperation.JWE);
        when(jwtClientConfigMock.getJWEAlgorithm()).thenReturn(JWEAlgorithm.AES);

        when(jwtClientConfigMock.getJwtSignature()).thenReturn(JWTSignature.HS256);
        when(jwtClientConfigMock.getHMACTokenSecret()).thenReturn(secret);

        jwtUserToken.init();

        UserPrincipal userPrincipal = new UserPrincipal("serialId", "JUnit", "Octopus");
        userPrincipal.getInfo().put(UserPrincipal.EXTERNAL_ID, "123");

        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();
        builder.addPermission("stringPermission");
        builder.addPermission(new NamedDomainPermission("namedPermission", "Test:*:*"));
        AuthorizationInfo info = builder.build();

        when(encryptionHandlerFactoryMock.getEncryptionHandler(JWEAlgorithm.AES)).thenReturn(encryptionHandlerMock);
        when(encryptionHandlerMock.doEncryption((String) isNull(), any(SignedJWT.class))).thenThrow(new JOSEException("X"));
        userPrincipal.addUserInfo("authorizationInfo", info);

        ReflectionUtil.injectDependencies(jwtUserToken, userPrincipal);

        jwtUserToken.createJWTUserToken(null, null);

    }


    private String getHMACSecret() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] secure = new byte[32];
        secureRandom.nextBytes(secure);
        return Base64.encodeToString(secure);
    }

    private String getHMACSecretShort() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] secure = new byte[16];
        secureRandom.nextBytes(secure);
        return Base64.encodeToString(secure);
    }

}