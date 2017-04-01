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
package be.c4j.ee.security.jwt.filter;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.jwt.JWTClaimsHandler;
import be.c4j.ee.security.jwt.JWTUser;
import be.c4j.ee.security.jwt.config.JWEAlgorithm;
import be.c4j.ee.security.jwt.config.JWTOperation;
import be.c4j.ee.security.jwt.config.JWTUserConfig;
import be.c4j.ee.security.jwt.encryption.DecryptionHandler;
import be.c4j.ee.security.jwt.encryption.DecryptionHandlerFactory;
import be.c4j.ee.security.util.SecretUtil;
import be.c4j.test.util.BeanManagerFake;
import be.c4j.test.util.ReflectionUtil;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.apache.shiro.UnavailableSecurityManagerException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class JWTAuthenticatingFilterTest {

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private JWTUserConfig jwtServerConfigMock;

    @Mock
    private DecryptionHandlerFactory decryptionHandlerFactoryMock;

    @Mock
    private DecryptionHandler decryptionHandlerMock;

    @Mock
    private JWTClaimsHandler jwtClaimsHandlerMock;

    @Mock
    private PrintWriter printWriterMock;

    @Captor
    private ArgumentCaptor<CharSequence> responseOutputCaptor;


    private JWTAuthenticatingFilter jwtAuthenticatingFilter;

    private BeanManagerFake beanManagerFake;

    private SecretUtil secretUtil;

    @Before
    public void setup() {
        jwtAuthenticatingFilter = new JWTAuthenticatingFilter();

        beanManagerFake = new BeanManagerFake();

        secretUtil = new SecretUtil();
        secretUtil.init();

    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test(expected = AuthenticationException.class)
    public void createToken_MissingAuthorizationHeader() throws Exception {
        jwtAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);
    }

    @Test(expected = AuthenticationException.class)
    public void createToken_WrongAuthorizationHeader_1() throws Exception {
        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("Wrong");
        jwtAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);
    }

    @Test(expected = AuthenticationException.class)
    public void createToken_WrongAuthorizationHeader_2() throws Exception {
        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("Still wrong");
        jwtAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);
    }

    @Test(expected = AuthenticationException.class)
    public void createToken_WrongToken() throws Exception {
        ReflectionUtil.injectDependencies(jwtAuthenticatingFilter, JWTOperation.JWT);

        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("Bearer wrong");
        jwtAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);

    }

    @Test(expected = OctopusConfigurationException.class)
    public void createToken_ShortSecret() throws Exception {

        beanManagerFake.registerBean(jwtServerConfigMock, JWTUserConfig.class);
        beanManagerFake.registerBean(decryptionHandlerFactoryMock, DecryptionHandlerFactory.class);

        beanManagerFake.endRegistration();

        when(jwtServerConfigMock.getJWTOperation()).thenReturn(JWTOperation.JWT);
        when(jwtServerConfigMock.getHMACTokenSecret()).thenReturn(secretUtil.generateSecretBase64(16));

        jwtAuthenticatingFilter.init();
    }

    @Test
    public void createToken_happyCase() throws Exception {

        beanManagerFake.registerBean(jwtServerConfigMock, JWTUserConfig.class);
        beanManagerFake.registerBean(decryptionHandlerFactoryMock, DecryptionHandlerFactory.class);

        beanManagerFake.endRegistration();

        String secret = secretUtil.generateSecretBase64(32);

        when(jwtServerConfigMock.getJWTOperation()).thenReturn(JWTOperation.JWT);
        when(jwtServerConfigMock.getHMACTokenSecret()).thenReturn(secret);

        jwtAuthenticatingFilter.init();

        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("Bearer " + createSignedJWT(secret).serialize());


        AuthenticationToken token = jwtAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);
        assertThat(token).isNotNull();
        assertThat(token).isInstanceOf(JWTUser.class);

        JWTUser jwtUser = (JWTUser) token;
        assertThat(jwtUser.getId()).isEqualTo("123");
        assertThat(jwtUser.getName()).isEqualTo("JUnit");
    }

    @Test(expected = AuthenticationException.class)
    public void createToken_happyCase_claimsHandler_notValid() throws Exception {

        beanManagerFake.registerBean(jwtServerConfigMock, JWTUserConfig.class);
        beanManagerFake.registerBean(decryptionHandlerFactoryMock, DecryptionHandlerFactory.class);
        beanManagerFake.registerBean(jwtClaimsHandlerMock, JWTClaimsHandler.class);

        beanManagerFake.endRegistration();

        String secret = secretUtil.generateSecretBase64(32);

        when(jwtServerConfigMock.getJWTOperation()).thenReturn(JWTOperation.JWT);
        when(jwtServerConfigMock.getHMACTokenSecret()).thenReturn(secret);

        jwtAuthenticatingFilter.init();

        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("Bearer " + createSignedJWT(secret).serialize());

        when(jwtClaimsHandlerMock.claimsAreValid(any(JWTClaimsSet.class))).thenReturn(false);

        jwtAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);
    }

    @Test
    public void createToken_happyCase_claimSetHandler() throws Exception {

        beanManagerFake.registerBean(jwtServerConfigMock, JWTUserConfig.class);
        beanManagerFake.registerBean(decryptionHandlerFactoryMock, DecryptionHandlerFactory.class);
        beanManagerFake.registerBean(jwtClaimsHandlerMock, JWTClaimsHandler.class);

        beanManagerFake.endRegistration();

        String secret = secretUtil.generateSecretBase64(32);

        when(jwtServerConfigMock.getJWTOperation()).thenReturn(JWTOperation.JWT);
        when(jwtServerConfigMock.getHMACTokenSecret()).thenReturn(secret);

        jwtAuthenticatingFilter.init();

        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("Bearer " + createSignedJWT(secret).serialize());

        when(jwtClaimsHandlerMock.claimsAreValid(any(JWTClaimsSet.class))).thenReturn(true);

        Map<String, Object> extras = new HashMap<String, Object>();
        extras.put("ExtraKey", "JUnit");
        when(jwtClaimsHandlerMock.defineAdditionalUserInfo(any(JWTUser.class))).thenReturn(extras);

        AuthenticationToken token = jwtAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);
        assertThat(token).isNotNull();
        assertThat(token).isInstanceOf(JWTUser.class);

        JWTUser jwtUser = (JWTUser) token;
        assertThat(jwtUser.getId()).isEqualTo("123");
        assertThat(jwtUser.getName()).isEqualTo("JUnit");

        assertThat(jwtUser.getUserInfo()).containsEntry("ExtraKey", "JUnit");
    }


    @Test(expected = AuthenticationException.class)
    public void createToken_InvalidToken() throws Exception {

        beanManagerFake.registerBean(jwtServerConfigMock, JWTUserConfig.class);
        beanManagerFake.registerBean(decryptionHandlerFactoryMock, DecryptionHandlerFactory.class);

        beanManagerFake.endRegistration();

        String secret = secretUtil.generateSecretBase64(32);

        when(jwtServerConfigMock.getJWTOperation()).thenReturn(JWTOperation.JWT);
        when(jwtServerConfigMock.getHMACTokenSecret()).thenReturn(secret);

        jwtAuthenticatingFilter.init();

        String signedJWT = createSignedJWT(secret).serialize();
        int idx = signedJWT.charAt('.');
        signedJWT = signedJWT.substring(0, idx + 2) + signedJWT.substring(idx + 4);

        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("Bearer " + signedJWT);


        AuthenticationToken token = jwtAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);
        assertThat(token).isNotNull();
        assertThat(token).isInstanceOf(JWTUser.class);

        JWTUser jwtUser = (JWTUser) token;
        assertThat(jwtUser.getId()).isEqualTo(123L);
        assertThat(jwtUser.getName()).isEqualTo("JUnit");
    }

    @Test(expected = AuthenticationException.class)
    public void createToken_expiredToken() throws Exception {

        beanManagerFake.registerBean(jwtServerConfigMock, JWTUserConfig.class);
        beanManagerFake.registerBean(decryptionHandlerFactoryMock, DecryptionHandlerFactory.class);

        beanManagerFake.endRegistration();

        String secret = secretUtil.generateSecretBase64(32);

        when(jwtServerConfigMock.getJWTOperation()).thenReturn(JWTOperation.JWT);
        when(jwtServerConfigMock.getHMACTokenSecret()).thenReturn(secret);

        jwtAuthenticatingFilter.init();

        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("Bearer " + createSignedJWT(secret));


        Thread.sleep(1500);  // Token is only 1 sec valid, so this makes it invalid.
        jwtAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);

    }

    @Test
    public void createToken_happyCase_encrypted() throws Exception {

        beanManagerFake.registerBean(jwtServerConfigMock, JWTUserConfig.class);
        beanManagerFake.registerBean(decryptionHandlerFactoryMock, DecryptionHandlerFactory.class);

        beanManagerFake.endRegistration();

        String secret = secretUtil.generateSecretBase64(32);

        when(jwtServerConfigMock.getJWTOperation()).thenReturn(JWTOperation.JWE);
        when(jwtServerConfigMock.getHMACTokenSecret()).thenReturn(secret);
        when(jwtServerConfigMock.getJWEAlgorithm()).thenReturn(JWEAlgorithm.AES);

        jwtAuthenticatingFilter.init();

        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("Bearer TheEncrypted");


        when(decryptionHandlerFactoryMock.getDecryptionHandler(JWEAlgorithm.AES)).thenReturn(decryptionHandlerMock);
        when(decryptionHandlerMock.doDecryption(null, "TheEncrypted")).thenReturn(createSignedJWT(secret));

        AuthenticationToken token = jwtAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);
        assertThat(token).isNotNull();
        assertThat(token).isInstanceOf(JWTUser.class);

        JWTUser jwtUser = (JWTUser) token;
        assertThat(jwtUser.getId()).isEqualTo("123");
        assertThat(jwtUser.getName()).isEqualTo("JUnit");
    }

    @Test(expected = OctopusUnexpectedException.class)
    public void createToken_encrypted_wrong() throws Exception {

        beanManagerFake.registerBean(jwtServerConfigMock, JWTUserConfig.class);
        beanManagerFake.registerBean(decryptionHandlerFactoryMock, DecryptionHandlerFactory.class);

        beanManagerFake.endRegistration();

        String secret = secretUtil.generateSecretBase64(32);

        when(jwtServerConfigMock.getJWTOperation()).thenReturn(JWTOperation.JWE);
        when(jwtServerConfigMock.getHMACTokenSecret()).thenReturn(secret);
        when(jwtServerConfigMock.getJWEAlgorithm()).thenReturn(JWEAlgorithm.AES);

        jwtAuthenticatingFilter.init();

        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("Bearer TheEncrypted");


        when(decryptionHandlerFactoryMock.getDecryptionHandler(JWEAlgorithm.AES)).thenReturn(decryptionHandlerMock);
        when(decryptionHandlerMock.doDecryption(null, "TheEncrypted")).thenThrow(new ParseException("X", 1));

        jwtAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);

    }

    private SignedJWT createSignedJWT(String secret) throws KeyLengthException {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);

        JWTClaimsSet.Builder claimSetBuilder = new JWTClaimsSet.Builder();
        claimSetBuilder.subject(createJSON());

        Date issueTime = new Date();
        claimSetBuilder.issueTime(issueTime);

        claimSetBuilder.expirationTime(addSecondsToDate(1, issueTime));

        SignedJWT signedJWT = new SignedJWT(header, claimSetBuilder.build());

        // Apply the HMAC

        JWSSigner signer = new MACSigner(secret);
        try {
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new OctopusUnexpectedException(e);
        }

        return signedJWT;
    }

    private String createJSON() {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("id", 123);
        jsonObject.put("name", "JUnit");
        jsonObject.put("permissions", new JSONArray());
        jsonObject.put("roles", new JSONArray());
        return jsonObject.toJSONString();
    }


    private Date addSecondsToDate(int seconds, Date beforeTime) {

        long curTimeInMs = beforeTime.getTime();
        return new Date(curTimeInMs + (seconds * 1000));
    }

    @Test(expected = AuthenticationException.class)
    public void onAccessDenied_missingHeader() throws Exception {
        jwtAuthenticatingFilter.onAccessDenied(httpServletRequestMock, httpServletResponseMock);
    }

    @Test(expected = UnavailableSecurityManagerException.class)
    // The idea we want to test is that everything goes well until we need to have the securityManager.
    // This is Shiro specific from that point so we assume it is ok.
    public void onAccessDenied_withHeader() throws Exception {

        beanManagerFake.registerBean(jwtServerConfigMock, JWTUserConfig.class);
        beanManagerFake.registerBean(decryptionHandlerFactoryMock, DecryptionHandlerFactory.class);

        beanManagerFake.endRegistration();

        String secret = secretUtil.generateSecretBase64(32);

        when(jwtServerConfigMock.getJWTOperation()).thenReturn(JWTOperation.JWT);
        when(jwtServerConfigMock.getHMACTokenSecret()).thenReturn(secret);

        jwtAuthenticatingFilter.init();

        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("Bearer " + createSignedJWT(secret).serialize());

        jwtAuthenticatingFilter.onAccessDenied(httpServletRequestMock, httpServletResponseMock);

    }

    @Test
    public void cleanup_checkErrorInfo() throws ServletException, IOException {
        when(httpServletResponseMock.getWriter()).thenReturn(printWriterMock);

        OctopusConfigurationException exception = new OctopusConfigurationException("Something went wrong");
        jwtAuthenticatingFilter.cleanup(httpServletRequestMock, httpServletResponseMock, exception);

        verify(printWriterMock).append(responseOutputCaptor.capture());
        assertThat(responseOutputCaptor.getValue()).isEqualTo("{\"code\":\"OCT-JWT-USER-001\", \"message\":\"Octopus Configuration exception: Something went wrong\"}");
    }

    @Test
    public void cleanup_checkErrorInfo_2() throws ServletException, IOException {
        when(httpServletResponseMock.getWriter()).thenReturn(printWriterMock);

        OctopusUnauthorizedException exception = new OctopusUnauthorizedException("Denied access", null);
        jwtAuthenticatingFilter.cleanup(httpServletRequestMock, httpServletResponseMock, exception);

        verify(printWriterMock).append(responseOutputCaptor.capture());
        assertThat(responseOutputCaptor.getValue()).isEqualTo("{\"code\":\"OCT-JWT-USER-011\", \"message\":\"Denied access\"}");

    }
}