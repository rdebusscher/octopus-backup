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

import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.session.SessionUtil;
import be.c4j.ee.security.sso.OctopusSSOUserConverter;
import be.c4j.ee.security.sso.SSOFlow;
import be.c4j.ee.security.sso.client.OpenIdVariableClientData;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import be.c4j.ee.security.util.SecretUtil;
import be.c4j.ee.security.util.TimeUtil;
import be.c4j.util.ReflectionUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import net.jadler.Jadler;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.util.SavedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.apache.shiro.web.util.WebUtils.SAVED_REQUEST_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class SSOCallbackServletTest {

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private HttpSession httpSessionMock;

    @Mock
    private OctopusConfig octopusConfigMock;

    @Mock
    private ExchangeForAccessCode exchangeForAccessCodeMock;

    @Mock
    private OctopusSSOClientConfiguration clientConfigurationMock;

    @Mock
    private CallbackErrorHandler callbackErrorHandlerMock;

    @Mock
    private SessionUtil sessionUtilMock;

    @Mock
    private Subject subjectMock;

    @Mock
    private Session sessionMock;

    @Captor
    private ArgumentCaptor<ErrorObject> errorObjectArgumentCaptor;

    @Captor
    private ArgumentCaptor<String> stringArgumentCaptor;

    @InjectMocks
    private SSOCallbackServlet callbackServlet;

    @Before
    public void setUp() throws IllegalAccessException {
        Jadler.initJadler();

        ReflectionUtil.injectDependencies(callbackServlet, new OctopusSSOUserConverter());
    }

    @After
    public void tearDown() {
        Jadler.closeJadler();
    }

    @Test
    public void doGet_ErrorResponse() throws ServletException, IOException {
        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);
        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");
        when(httpSessionMock.getAttribute(OpenIdVariableClientData.class.getName())).thenReturn(clientData);

        when(httpServletRequestMock.getQueryString()).thenReturn("error_description=Invalid+request%3A+Missing+%22client_id%22+parameter&state=stateCode&error=invalid_request");

        callbackServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCaptor.capture());

        assertThat(errorObjectArgumentCaptor.getValue().getDescription()).isEqualTo("Invalid request: Missing \"client_id\" parameter");
    }

    @Test
    public void doGet_InvalidRequest_NoState() throws ServletException, IOException {
        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);
        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");
        when(httpSessionMock.getAttribute(OpenIdVariableClientData.class.getName())).thenReturn(clientData);

        when(httpServletRequestMock.getQueryString()).thenReturn("blablabla=wrong");

        callbackServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCaptor.capture());

        assertThat(errorObjectArgumentCaptor.getValue().getDescription()).isEqualTo("Request has an invalid 'state' value");
        assertThat(errorObjectArgumentCaptor.getValue().getCode()).isEqualTo("OCT-SSO-CLIENT-011");
    }


    @Test
    public void doGet_InvalidRequest_MissingSession() throws ServletException, IOException {
        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);

        when(httpSessionMock.getAttribute(OpenIdVariableClientData.class.getName())).thenReturn(null);

        //when(httpServletResponseMock.getWriter()).thenReturn(printWriterMock);

        callbackServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCaptor.capture());

        assertThat(errorObjectArgumentCaptor.getValue().getDescription()).isEqualTo("Request did not originate from this session");
        assertThat(errorObjectArgumentCaptor.getValue().getCode()).isEqualTo("OCT-SSO-CLIENT-012");
    }


    @Test
    public void doGet_WrongState() throws ServletException, IOException {
        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);
        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");
        when(httpSessionMock.getAttribute(OpenIdVariableClientData.class.getName())).thenReturn(clientData);

        when(httpServletRequestMock.getQueryString()).thenReturn("code=TheAuthenticationCode&state=stateValue");

        callbackServlet.doGet(httpServletRequestMock, httpServletResponseMock);
        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCaptor.capture());

        assertThat(errorObjectArgumentCaptor.getValue().getDescription()).isEqualTo("Request has an invalid 'state' value");
        assertThat(errorObjectArgumentCaptor.getValue().getCode()).isEqualTo("OCT-SSO-CLIENT-011");
    }


    @Test
    public void doGet_MissingAuthorizationCode() throws ServletException, IOException, ParseException {
        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);
        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");
        when(httpSessionMock.getAttribute(OpenIdVariableClientData.class.getName())).thenReturn(clientData);

        List<Audience> audience = new ArrayList<Audience>();
        IDTokenClaimsSet tokenClaimsSet = new IDTokenClaimsSet(new Issuer("Issuer")
                , new com.nimbusds.oauth2.sdk.id.Subject("subject"), audience, new Date(), new Date());
        String idToken = new PlainJWT(tokenClaimsSet.toJWTClaimsSet()).serialize();
        when(httpServletRequestMock.getQueryString()).thenReturn("id_token=" + idToken + "&state=" + clientData.getState().getValue());

        when(clientConfigurationMock.getSSOType()).thenReturn(SSOFlow.AUTHORIZATION_CODE);

        callbackServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCaptor.capture());
        assertThat(errorObjectArgumentCaptor.getValue().getCode()).isEqualTo("OCT-SSO-CLIENT-013");
    }

    @Test
    public void doGet_ValidAuthenticationToken() throws ServletException, IOException {
        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);
        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");
        when(httpSessionMock.getAttribute(OpenIdVariableClientData.class.getName())).thenReturn(clientData);

        when(httpServletRequestMock.getQueryString()).thenReturn("code=TheAuthorizationCode&state=" + clientData.getState().getValue());

        when(clientConfigurationMock.getSSOType()).thenReturn(SSOFlow.AUTHORIZATION_CODE);
        when(clientConfigurationMock.getSSOClientId()).thenReturn("JUnit_client");

        AuthorizationCode authorizationCode = new AuthorizationCode("TheAuthorizationCode");
        when(exchangeForAccessCodeMock.doExchange(httpServletResponseMock, clientData, authorizationCode)).thenReturn(new BearerAccessToken("TheAccessToken"));

        when(clientConfigurationMock.getUserInfoEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/user");

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
                .withContentType("application/jwt");

        when(clientConfigurationMock.getSSOIdTokenSecret()).thenReturn(secret.getBytes());
        when(clientConfigurationMock.getSSOServer()).thenReturn("http://localhost/oidc");

        ThreadContext.bind(subjectMock);
        when(subjectMock.getSession(false)).thenReturn(sessionMock);
        when(subjectMock.getSession()).thenReturn(sessionMock);
        when(httpServletRequestMock.getRequestURI()).thenReturn("http://host.to.saved.request/root");
        SavedRequest savedRequest = new SavedRequest(httpServletRequestMock);
        when(sessionMock.getAttribute(SAVED_REQUEST_KEY)).thenReturn(savedRequest);

        callbackServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(sessionUtilMock).invalidateCurrentSession(httpServletRequestMock);

        verify(httpServletResponseMock).sendRedirect(stringArgumentCaptor.capture());
        assertThat(stringArgumentCaptor.getValue()).startsWith("http://host.to.saved.request/root?code=TheAuthorizationCode&state=");
        // The query part is added to requestURL because it was mocked earlier like that to have a correct behaviour for other parts (state is variable !)

        verify(callbackErrorHandlerMock, never()).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCaptor.capture());

    }

    // FIXME The other scenarios.
}