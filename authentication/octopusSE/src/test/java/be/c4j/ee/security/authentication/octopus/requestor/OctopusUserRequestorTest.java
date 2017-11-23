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
package be.c4j.ee.security.authentication.octopus.requestor;

import be.c4j.ee.security.authentication.octopus.OctopusSEConfiguration;
import be.c4j.ee.security.authentication.octopus.exception.OctopusRetrievalException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.OctopusSSOUserConverter;
import be.c4j.ee.security.sso.client.OpenIdVariableClientData;
import be.c4j.ee.security.sso.rest.PrincipalUserInfoJSONProvider;
import be.c4j.ee.security.util.SecretUtil;
import be.c4j.ee.security.util.TimeUtil;
import be.c4j.test.util.ReflectionUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.jadler.Jadler;
import net.minidev.json.JSONObject;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class OctopusUserRequestorTest {

    private static final String APPLICATION_JWT = "application/jwt";

    @Mock
    private OctopusSEConfiguration configurationMock;

    @Mock
    private OctopusSSOUserConverter octopusSSOUserConverterMock;

    @Mock
    private PrincipalUserInfoJSONProvider userInfoJSONProviderMock;

    @InjectMocks
    private OctopusUserRequestor octopusUserRequestor;

    @Before
    public void setUp() throws IllegalAccessException {
        Jadler.initJadler();

        ReflectionUtil.injectDependencies(octopusUserRequestor, new OctopusSSOUserConverter());
    }

    @After
    public void tearDown() {
        Jadler.closeJadler();
    }

    @Test
    public void getOctopusSSOUser() throws ParseException, JOSEException, OctopusRetrievalException, com.nimbusds.oauth2.sdk.ParseException, URISyntaxException {

        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");

        TimeUtil timeUtil = new TimeUtil();

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.subject("JUnit");
        builder.issuer("http://localhost/oidc");
        builder.audience("JUnit_client");
        builder.claim("nonce", clientData.getNonce().getValue());
        builder.expirationTime(timeUtil.addSecondsToDate(2, new Date()));

        SecretUtil secretUtil = new SecretUtil();
        secretUtil.init();
        String secret = secretUtil.generateSecretBase64(32);

        when(configurationMock.getUserInfoEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/user");
        when(configurationMock.getOctopusSSOServer()).thenReturn("http://localhost/oidc");
        when(configurationMock.getSSOClientId()).thenReturn("JUnit_client");
        when(configurationMock.getSSOIdTokenSecret()).thenReturn(secret.getBytes());

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, builder.build());

        try {
            signedJWT.sign(new MACSigner(secret));
        } catch (JOSEException e) {
            throw new OctopusUnexpectedException(e);
        }
        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/oidc/octopus/sso/user")
                .havingHeaderEqualTo("Authorization", "Bearer TheAccessToken")
                .respond()
                .withBody(signedJWT.serialize())
                .withContentType(APPLICATION_JWT);


        BearerAccessToken accessToken = new BearerAccessToken("TheAccessToken");

        OctopusSSOUser ssoUser = octopusUserRequestor.getOctopusSSOUser(clientData, accessToken);

        assertThat(ssoUser.getAccessToken()).isEqualTo(accessToken.getValue());
        assertThat(ssoUser.getUserInfo()).hasSize(5);
    }

    @Test(expected = OctopusRetrievalException.class)
    public void getOctopusSSOUser_expired() throws ParseException, JOSEException, OctopusRetrievalException, com.nimbusds.oauth2.sdk.ParseException, URISyntaxException {

        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.subject("JUnit");
        builder.issuer("http://localhost/oidc");
        builder.audience("JUnit_client");
        builder.claim("nonce", clientData.getNonce().getValue());
        builder.expirationTime(new Date());

        SecretUtil secretUtil = new SecretUtil();
        secretUtil.init();
        String secret = secretUtil.generateSecretBase64(32);

        when(configurationMock.getUserInfoEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/user");
        when(configurationMock.getOctopusSSOServer()).thenReturn("http://localhost/oidc");
        when(configurationMock.getSSOClientId()).thenReturn("JUnit_client");
        when(configurationMock.getSSOIdTokenSecret()).thenReturn(secret.getBytes());

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, builder.build());

        try {
            signedJWT.sign(new MACSigner(secret));
        } catch (JOSEException e) {
            throw new OctopusUnexpectedException(e);
        }
        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/oidc/octopus/sso/user")
                .havingHeaderEqualTo("Authorization", "Bearer TheAccessToken")
                .respond()
                .withBody(signedJWT.serialize())
                .withContentType(APPLICATION_JWT);


        BearerAccessToken accessToken = new BearerAccessToken("TheAccessToken");

        OctopusSSOUser ssoUser = octopusUserRequestor.getOctopusSSOUser(clientData, accessToken);

        assertThat(ssoUser.getAccessToken()).isEqualTo(accessToken.getValue());
        assertThat(ssoUser.getUserInfo()).hasSize(5);
    }

    @Test(expected = OctopusRetrievalException.class)
    public void getOctopusSSOUser_invalidSignature() throws ParseException, JOSEException, OctopusRetrievalException, com.nimbusds.oauth2.sdk.ParseException, URISyntaxException {

        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");

        TimeUtil timeUtil = new TimeUtil();

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.subject("JUnit");
        builder.issuer("http://localhost/oidc");
        builder.audience("JUnit_client");
        builder.claim("nonce", clientData.getNonce().getValue());
        builder.expirationTime(new Date());

        SecretUtil secretUtil = new SecretUtil();
        secretUtil.init();
        String secret = secretUtil.generateSecretBase64(32);

        when(configurationMock.getUserInfoEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/user");
        when(configurationMock.getSSOIdTokenSecret()).thenReturn(secret.getBytes());

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, builder.build());

        try {
            signedJWT.sign(new MACSigner(secret));
        } catch (JOSEException e) {
            throw new OctopusUnexpectedException(e);
        }
        StringBuilder jwtString = new StringBuilder(signedJWT.serialize());
        jwtString.deleteCharAt(jwtString.length() - 10);  // By removing a character, we make the sign invalid

        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/oidc/octopus/sso/user")
                .havingHeaderEqualTo("Authorization", "Bearer TheAccessToken")
                .respond()
                .withBody(jwtString.toString())
                .withContentType(APPLICATION_JWT);


        BearerAccessToken accessToken = new BearerAccessToken("TheAccessToken");

        OctopusSSOUser ssoUser = octopusUserRequestor.getOctopusSSOUser(clientData, accessToken);

        assertThat(ssoUser.getAccessToken()).isEqualTo(accessToken.getValue());
        assertThat(ssoUser.getUserInfo()).hasSize(5);
    }

    @Test(expected = OctopusRetrievalException.class)
    public void getOctopusSSOUser_missingNonce() throws ParseException, JOSEException, OctopusRetrievalException, com.nimbusds.oauth2.sdk.ParseException, URISyntaxException {

        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");

        TimeUtil timeUtil = new TimeUtil();

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.subject("JUnit");
        builder.issuer("http://localhost/oidc");
        builder.audience("JUnit_client");
        builder.expirationTime(timeUtil.addSecondsToDate(2, new Date()));

        SecretUtil secretUtil = new SecretUtil();
        secretUtil.init();
        String secret = secretUtil.generateSecretBase64(32);

        when(configurationMock.getUserInfoEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/user");
        when(configurationMock.getOctopusSSOServer()).thenReturn("http://localhost/oidc");
        when(configurationMock.getSSOClientId()).thenReturn("JUnit_client");
        when(configurationMock.getSSOIdTokenSecret()).thenReturn(secret.getBytes());

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, builder.build());

        try {
            signedJWT.sign(new MACSigner(secret));
        } catch (JOSEException e) {
            throw new OctopusUnexpectedException(e);
        }
        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/oidc/octopus/sso/user")
                .havingHeaderEqualTo("Authorization", "Bearer TheAccessToken")
                .respond()
                .withBody(signedJWT.serialize())
                .withContentType(APPLICATION_JWT);


        BearerAccessToken accessToken = new BearerAccessToken("TheAccessToken");

        octopusUserRequestor.getOctopusSSOUser(clientData, accessToken);

    }

    @Test
    public void getOctopusSSOUser_missingAud() throws ParseException, JOSEException, OctopusRetrievalException, com.nimbusds.oauth2.sdk.ParseException, URISyntaxException {

        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");

        TimeUtil timeUtil = new TimeUtil();

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.subject("JUnit");
        builder.issuer("http://localhost/oidc");
        builder.audience("JUnit_client");
        builder.claim("nonce", clientData.getNonce().getValue());
        builder.expirationTime(timeUtil.addSecondsToDate(2, new Date()));

        SecretUtil secretUtil = new SecretUtil();
        secretUtil.init();
        String secret = secretUtil.generateSecretBase64(32);

        when(configurationMock.getUserInfoEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/user");
        when(configurationMock.getOctopusSSOServer()).thenReturn("http://localhost/oidc");
        when(configurationMock.getSSOClientId()).thenReturn("anotherClient");
        when(configurationMock.getSSOIdTokenSecret()).thenReturn(secret.getBytes());

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, builder.build());

        try {
            signedJWT.sign(new MACSigner(secret));
        } catch (JOSEException e) {
            throw new OctopusUnexpectedException(e);
        }
        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/oidc/octopus/sso/user")
                .havingHeaderEqualTo("Authorization", "Bearer TheAccessToken")
                .respond()
                .withBody(signedJWT.serialize())
                .withContentType(APPLICATION_JWT);


        BearerAccessToken accessToken = new BearerAccessToken("TheAccessToken");

        try {
            octopusUserRequestor.getOctopusSSOUser(clientData, accessToken);
            Assert.fail("Exception expected");
        } catch (OctopusRetrievalException e) {
            assertThat(e.getMessage()).isEqualTo("JWT claim Validation failed : aud");
        }

    }

    @Test
    public void getOctopusSSOUser_customValidator() throws ParseException, JOSEException, OctopusRetrievalException, com.nimbusds.oauth2.sdk.ParseException, URISyntaxException, IllegalAccessException {
        // Inject custom validator
        CustomUserInfoValidator customUserInfoValidatorMock = Mockito.mock(CustomUserInfoValidator.class);
        ReflectionUtil.injectDependencies(octopusUserRequestor, customUserInfoValidatorMock);

        // Change List of Claims
        List<String> wrongClaims = new ArrayList<String>();
        wrongClaims.add("JUnit");
        when(customUserInfoValidatorMock.validateUserInfo(any(UserInfo.class), any(OpenIdVariableClientData.class), ArgumentMatchers.<String>anyList()))
                .thenReturn(wrongClaims);

        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");

        TimeUtil timeUtil = new TimeUtil();

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.subject("JUnit");
        builder.issuer("http://localhost/oidc");
        builder.audience("JUnit_client");
        builder.claim("nonce", clientData.getNonce().getValue());
        builder.expirationTime(timeUtil.addSecondsToDate(2, new Date()));

        SecretUtil secretUtil = new SecretUtil();
        secretUtil.init();
        String secret = secretUtil.generateSecretBase64(32);

        when(configurationMock.getUserInfoEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/user");
        when(configurationMock.getOctopusSSOServer()).thenReturn("http://localhost/oidc");
        when(configurationMock.getSSOClientId()).thenReturn("anotherClient");
        when(configurationMock.getSSOIdTokenSecret()).thenReturn(secret.getBytes());

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, builder.build());

        try {
            signedJWT.sign(new MACSigner(secret));
        } catch (JOSEException e) {
            throw new OctopusUnexpectedException(e);
        }
        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/oidc/octopus/sso/user")
                .havingHeaderEqualTo("Authorization", "Bearer TheAccessToken")
                .respond()
                .withBody(signedJWT.serialize())
                .withContentType(APPLICATION_JWT);


        BearerAccessToken accessToken = new BearerAccessToken("TheAccessToken");

        try {
            octopusUserRequestor.getOctopusSSOUser(clientData, accessToken);
            Assert.fail("Exception expected");
        } catch (OctopusRetrievalException e) {
            assertThat(e.getMessage()).isEqualTo("JWT claim Validation failed : JUnit");
        }

    }

    @Test(expected = OctopusRetrievalException.class)
    public void getOctopusSSOUser_ErrorReturn() throws ParseException, JOSEException, OctopusRetrievalException, com.nimbusds.oauth2.sdk.ParseException, URISyntaxException {

        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");

        when(configurationMock.getUserInfoEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/user");


        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/oidc/octopus/sso/user")
                .havingHeaderEqualTo("Authorization", "Bearer TheAccessToken")
                .respond()
                .withStatus(400)
                .withBody("{}")
                .withContentType(APPLICATION_JWT);


        BearerAccessToken accessToken = new BearerAccessToken("TheAccessToken");

        octopusUserRequestor.getOctopusSSOUser(clientData, accessToken);


    }

    @Test
    public void getOctopusSSOUser_plainJSONResult() throws ParseException, JOSEException, OctopusRetrievalException, com.nimbusds.oauth2.sdk.ParseException, URISyntaxException {

        OpenIdVariableClientData clientData = new OpenIdVariableClientData();


        when(configurationMock.getUserInfoEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/user");
        when(configurationMock.getOctopusSSOServer()).thenReturn("http://localhost/oidc");

        TimeUtil timeUtil = new TimeUtil();
        JSONObject json = new JSONObject();
        json.put("sub", "JUnit");
        json.put("iss", "http://localhost/oidc");
        json.put("exp", timeUtil.addSecondsToDate(2, new Date()).getTime());


        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/oidc/octopus/sso/user")
                .havingHeaderEqualTo("Authorization", "Bearer TheAccessToken")
                .respond()
                .withBody(json.toJSONString())
                .withContentType("application/json");


        BearerAccessToken accessToken = new BearerAccessToken("TheAccessToken");

        OctopusSSOUser ssoUser = octopusUserRequestor.getOctopusSSOUser(clientData, accessToken);

        assertThat(ssoUser.getAccessToken()).isEqualTo(accessToken.getValue());
        assertThat(ssoUser.getUserInfo()).hasSize(3);
        assertThat(ssoUser.getUserInfo()).containsKeys("sub", "iss", "exp");
    }

}