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
package be.c4j.ee.security.sso.client.callback;

import be.c4j.ee.security.config.Debug;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.sso.client.OpenIdVariableClientData;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import be.c4j.ee.security.util.TimeUtil;
import be.c4j.test.util.ReflectionUtil;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.jadler.Jadler;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class ExchangeForAccessCodeTest {

    @Mock
    private OctopusConfig octopusConfigMock;

    @Mock
    private OctopusSSOClientConfiguration clientConfigurationMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private CallbackErrorHandler callbackErrorHandlerMock;

    @InjectMocks
    private ExchangeForAccessCode exchangeForAccessCode;

    @Captor
    private ArgumentCaptor<ErrorObject> errorObjectArgumentCaptor;

    @Before
    public void setUp() {
        Jadler.initJadler();
        when(octopusConfigMock.showDebugFor()).thenReturn(Collections.<Debug>emptyList());
    }

    @After
    public void tearDown() {
        Jadler.closeJadler();
    }

    @Test
    public void init_secretShort() throws NoSuchFieldException, IllegalAccessException {

        defineSecret(256 / 8 + 1);

        exchangeForAccessCode.init();

        JWSAlgorithm algorithm = ReflectionUtil.getFieldValue(exchangeForAccessCode, "algorithm");
        assertThat(algorithm).isEqualTo(JWSAlgorithm.HS256);
    }

    @Test
    public void init_secretMedium() throws NoSuchFieldException, IllegalAccessException {

        defineSecret(384 / 8 + 1);

        exchangeForAccessCode.init();

        JWSAlgorithm algorithm = ReflectionUtil.getFieldValue(exchangeForAccessCode, "algorithm");
        assertThat(algorithm).isEqualTo(JWSAlgorithm.HS384);
    }

    @Test
    public void init_secretLong() throws NoSuchFieldException, IllegalAccessException {

        defineSecret(512 / 8 + 1);

        exchangeForAccessCode.init();

        JWSAlgorithm algorithm = ReflectionUtil.getFieldValue(exchangeForAccessCode, "algorithm");
        assertThat(algorithm).isEqualTo(JWSAlgorithm.HS512);
    }

    private void defineSecret(int byteLength) {
        byte[] bytes = new byte[byteLength];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(bytes);

        when(clientConfigurationMock.getSSOClientSecret()).thenReturn(bytes);

    }

    @Test
    public void doExchange_happyCase() throws IOException, ParseException {
        defineSecret(256 / 8 + 1);
        exchangeForAccessCode.init();

        when(clientConfigurationMock.getTokenEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/token");
        when(clientConfigurationMock.getSSOClientId()).thenReturn("junit_client");

        OpenIdVariableClientData variableClientData = new OpenIdVariableClientData("http://some.server/oidc");
        AuthorizationCode authorizationCode = new AuthorizationCode("TheAuthorizationCode");

        OIDCTokens token = defineTokens(variableClientData, 2);
        OIDCTokenResponse oidcTokenResponse = new OIDCTokenResponse(token);

        when(clientConfigurationMock.getSSOServer()).thenReturn("http://some.server/oidc");
        when(clientConfigurationMock.getSSOClientId()).thenReturn("junit_client");

        Jadler.onRequest()
                .havingPathEqualTo("/oidc/octopus/sso/token")
                .respond()
                .withContentType(CommonContentTypes.APPLICATION_JSON.toString())
                .withBody(oidcTokenResponse.toJSONObject().toJSONString());

        BearerAccessToken accessToken = exchangeForAccessCode.doExchange(httpServletResponseMock, variableClientData, authorizationCode);

        assertThat(accessToken).isNotNull();
        assertThat(accessToken).isEqualTo(accessToken);

        StringBaseMatcher bodyMatcher = new StringBaseMatcher();
        Jadler.verifyThatRequest()
                .havingMethodEqualTo("POST")
                .havingBody(bodyMatcher)
                .receivedOnce();

        assertThat(bodyMatcher.getBody()).startsWith("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=TheAuthorizationCode&grant_type=authorization_code&redirect_uri=http%3A%2F%2Fsome.server%2Foidc%2Foctopus%2Fsso%2FSSOCallback&client_assertion=eyJhbGciOiJIUzI1NiJ9.");

        verifyNoMoreInteractions(callbackErrorHandlerMock);
    }

    @Test
    public void doExchange_clientAuthenticationJWTExpired() throws IOException, ParseException {
        defineSecret(256 / 8 + 1);
        exchangeForAccessCode.init();

        when(clientConfigurationMock.getTokenEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/token");
        when(clientConfigurationMock.getSSOClientId()).thenReturn("junit_client");

        OpenIdVariableClientData variableClientData = new OpenIdVariableClientData("http://some.server/oidc");
        AuthorizationCode authorizationCode = new AuthorizationCode("TheAuthorizationCode");

        OIDCTokens token = defineTokens(variableClientData, -1);
        OIDCTokenResponse oidcTokenResponse = new OIDCTokenResponse(token);

        when(clientConfigurationMock.getSSOServer()).thenReturn("http://some.server/oidc");
        when(clientConfigurationMock.getSSOClientId()).thenReturn("junit_client");

        Jadler.onRequest()
                .havingPathEqualTo("/oidc/octopus/sso/token")
                .respond()
                .withContentType(CommonContentTypes.APPLICATION_JSON.toString())
                .withBody(oidcTokenResponse.toJSONObject().toJSONString());

        BearerAccessToken accessToken = exchangeForAccessCode.doExchange(httpServletResponseMock, variableClientData, authorizationCode);

        assertThat(accessToken).isNull();

        StringBaseMatcher bodyMatcher = new StringBaseMatcher();
        Jadler.verifyThatRequest()
                .havingMethodEqualTo("POST")
                .havingBody(bodyMatcher)
                .receivedOnce();

        assertThat(bodyMatcher.getBody()).startsWith("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=TheAuthorizationCode&grant_type=authorization_code&redirect_uri=http%3A%2F%2Fsome.server%2Foidc%2Foctopus%2Fsso%2FSSOCallback&client_assertion=eyJhbGciOiJIUzI1NiJ9.");

        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCaptor.capture());
        assertThat(errorObjectArgumentCaptor.getValue().getDescription()).isEqualTo("Validation of ID token JWT failed : Expired JWT");
    }

    @Test
    public void doExchange_errorResponse() throws IOException, ParseException {
        defineSecret(256 / 8 + 1);
        exchangeForAccessCode.init();

        when(clientConfigurationMock.getTokenEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/token");
        when(clientConfigurationMock.getSSOClientId()).thenReturn("junit_client");

        OpenIdVariableClientData variableClientData = new OpenIdVariableClientData("http://some.server/oidc");
        AuthorizationCode authorizationCode = new AuthorizationCode("TheAuthorizationCode");

        Jadler.onRequest()
                .havingPathEqualTo("/oidc/octopus/sso/token")
                .respond()
                .withStatus(HTTPResponse.SC_BAD_REQUEST)
                .withContentType(CommonContentTypes.APPLICATION_JSON.toString())
                .withBody("{\"error\":\"error code 1\",\"error_description\":\"some error description\"}");

        BearerAccessToken accessToken = exchangeForAccessCode.doExchange(httpServletResponseMock, variableClientData, authorizationCode);

        assertThat(accessToken).isNull();

        StringBaseMatcher bodyMatcher = new StringBaseMatcher();
        Jadler.verifyThatRequest()
                .havingMethodEqualTo("POST")
                .havingBody(bodyMatcher)
                .receivedOnce();

        assertThat(bodyMatcher.getBody()).startsWith("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=TheAuthorizationCode&grant_type=authorization_code&redirect_uri=http%3A%2F%2Fsome.server%2Foidc%2Foctopus%2Fsso%2FSSOCallback&client_assertion=eyJhbGciOiJIUzI1NiJ9.");

        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCaptor.capture());
        assertThat(errorObjectArgumentCaptor.getValue().getDescription()).isEqualTo("some error description");
    }

    private OIDCTokens defineTokens(OpenIdVariableClientData variableClientData, int addSeconds) throws ParseException {
        TimeUtil timeUtil = new TimeUtil();

        List<Audience> audiences = new ArrayList<Audience>();
        audiences.add(new Audience("junit_client"));

        IDTokenClaimsSet idTokenClaimSet = new IDTokenClaimsSet(new Issuer("http://some.server/oidc"),
                new Subject("JUnit"), audiences, timeUtil.addSecondsToDate(addSeconds, new Date()), new Date());
        idTokenClaimSet.setNonce(variableClientData.getNonce());

        PlainJWT plainJWT = new PlainJWT(idTokenClaimSet.toJWTClaimsSet());

        AccessToken accessCode = new BearerAccessToken("TheAccessCode");

        return new OIDCTokens(plainJWT, accessCode, null);
    }

    private class StringBaseMatcher extends BaseMatcher<String> {

        private String body;

        @Override
        public boolean matches(Object item) {
            body = item.toString();
            return true;
        }

        @Override
        public void describeTo(Description description) {

        }

        public String getBody() {
            return body;
        }
    }
}