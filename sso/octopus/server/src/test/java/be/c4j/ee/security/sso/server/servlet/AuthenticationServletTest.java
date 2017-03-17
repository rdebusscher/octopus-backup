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
package be.c4j.ee.security.sso.server.servlet;

import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.server.SSOProducerBean;
import be.c4j.ee.security.sso.server.client.ClientInfo;
import be.c4j.ee.security.sso.server.client.ClientInfoRetriever;
import be.c4j.ee.security.sso.server.config.SSOServerConfiguration;
import be.c4j.ee.security.sso.server.store.OIDCStoreData;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;
import be.c4j.ee.security.util.TimeUtil;
import be.c4j.ee.security.util.URLUtil;
import be.c4j.test.util.BeanManagerFake;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.apache.shiro.codec.Base64;
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
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthenticationServletTest {

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private SSOProducerBean ssoProducerBeanMock;

    @Mock
    private SSOServerConfiguration ssoServerConfiguration;

    @Mock
    private AuthenticationRequest authenticationRequestMock;

    @Mock
    private URLUtil urlUtilMock;

    @Mock
    private TimeUtil timeUtilMock;

    @Mock
    private SSOTokenStore tokenStoreMock;

    @Mock
    private ClientInfoRetriever clientInfoRetrieverMock;

    @Mock
    private HttpSession httpSessionMock;

    @Mock
    private OctopusConfig octopusConfigMock;

    @Captor
    private ArgumentCaptor<String> stringArgumentCaptor;
    @Captor
    private ArgumentCaptor<String> cookieTokenArgumentCaptor;
    @Captor
    private ArgumentCaptor<String> userAgentArgumentCaptor;
    @Captor
    private ArgumentCaptor<String> remoteHostArgumentCaptor;

    @Captor
    private ArgumentCaptor<OIDCStoreData> oidcStoreDataArgumentCaptor;

    @InjectMocks
    private AuthenticationServlet authenticationServlet;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() throws IllegalAccessException {
        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean(new TimeUtil(), TimeUtil.class);

        beanManagerFake.endRegistration();
    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void doGet_happyCase_CodeFlow() throws ServletException, IOException, ParseException, URISyntaxException {
        OctopusSSOUser ssoUser = new OctopusSSOUser();
        ssoUser.setFullName("JUnit test");
        ssoUser.setCookieToken("CookieTokenRememberMe");
        when(ssoProducerBeanMock.getOctopusSSOUser()).thenReturn(ssoUser);

        when(timeUtilMock.addSecondsToDate(anyLong(), any(Date.class))).thenReturn(new Date());
        when(ssoServerConfiguration.getOIDCTokenLength()).thenReturn(48);
        when(ssoServerConfiguration.getSSOAccessTokenTimeToLive()).thenReturn(3600);

        when(httpServletRequestMock.getAttribute(AbstractRequest.class.getName())).thenReturn(authenticationRequestMock);
        when(authenticationRequestMock.getResponseType()).thenReturn(ResponseType.parse("code"));
        when(authenticationRequestMock.getClientID()).thenReturn(new ClientID("JUnit_client"));
        when(authenticationRequestMock.getRedirectionURI()).thenReturn(new URI("http://client.app/testing"));
        when(authenticationRequestMock.getState()).thenReturn(new State("stateValue"));
        when(authenticationRequestMock.getNonce()).thenReturn(new Nonce("nonceValue"));
        when(authenticationRequestMock.getScope()).thenReturn(Scope.parse("scope1 scope2"));

        when(httpServletRequestMock.getSession()).thenReturn(httpSessionMock);

        when(httpServletRequestMock.getHeader("User-Agent")).thenReturn("UserAgentValue");
        when(httpServletRequestMock.getRemoteAddr()).thenReturn("remoteAddressValue");

        when(urlUtilMock.determineRoot(httpServletRequestMock)).thenReturn("http://some.host/root");

        authenticationServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(stringArgumentCaptor.capture());

        String callbackURL = stringArgumentCaptor.getValue();
        assertThat(callbackURL).startsWith("http://client.app/testing?code=");
        assertThat(callbackURL).endsWith("&state=stateValue");

        String authorizationCode = callbackURL.substring(31, callbackURL.indexOf('&'));
        byte[] bytes = Base64.decode(authorizationCode);
        assertThat(bytes.length >= 45 && bytes.length <= 48).isTrue(); // Don't know why the actual length isn't 48

        verify(tokenStoreMock).addLoginFromClient(any(OctopusSSOUser.class), cookieTokenArgumentCaptor.capture(),
                userAgentArgumentCaptor.capture(), remoteHostArgumentCaptor.capture(), oidcStoreDataArgumentCaptor.capture());

        assertThat(cookieTokenArgumentCaptor.getValue()).isEqualTo("CookieTokenRememberMe");
        assertThat(userAgentArgumentCaptor.getValue()).isEqualTo("UserAgentValue");
        assertThat(remoteHostArgumentCaptor.getValue()).isEqualTo("remoteAddressValue");

        assertThat(oidcStoreDataArgumentCaptor.getValue().getAuthorizationCode().getValue()).isEqualTo(authorizationCode);
        assertThat(oidcStoreDataArgumentCaptor.getValue().getAccessToken()).isNotNull();
        assertThat(oidcStoreDataArgumentCaptor.getValue().getScope().toStringList()).containsExactly("scope1", "scope2");
        assertThat(oidcStoreDataArgumentCaptor.getValue().getClientId().getValue()).isEqualTo("JUnit_client");

        IDTokenClaimsSet claimsSet = oidcStoreDataArgumentCaptor.getValue().getIdTokenClaimsSet();

        checkIdToken(claimsSet);

        verify(httpSessionMock).invalidate();
    }

    private void checkIdToken(IDTokenClaimsSet claimsSet) {
        assertThat(claimsSet.getAudience()).containsExactly(new Audience("JUnit_client"));
        assertThat(claimsSet.getIssuer()).isEqualTo(new Issuer("http://some.host/root"));
        assertThat(claimsSet.getSubject()).isEqualTo(new Subject("JUnit test"));
        assertThat(claimsSet.getExpirationTime()).isNotNull();
        assertThat(claimsSet.getIssueTime()).isNotNull();
        assertThat(claimsSet.getNonce()).isEqualTo(Nonce.parse("nonceValue"));
    }


    @Test
    public void doGet_happyCase_ImplicitFlow_IdTokenOnly() throws ServletException, IOException, ParseException, URISyntaxException, java.text.ParseException, JOSEException {
        OctopusSSOUser ssoUser = new OctopusSSOUser();
        ssoUser.setFullName("JUnit test");
        ssoUser.setCookieToken("CookieTokenRememberMe");
        when(ssoProducerBeanMock.getOctopusSSOUser()).thenReturn(ssoUser);

        when(timeUtilMock.addSecondsToDate(anyLong(), any(Date.class))).thenReturn(new Date());
        when(ssoServerConfiguration.getOIDCTokenLength()).thenReturn(48);

        when(httpServletRequestMock.getAttribute(AbstractRequest.class.getName())).thenReturn(authenticationRequestMock);
        when(authenticationRequestMock.getResponseType()).thenReturn(ResponseType.parse("id_token"));
        when(authenticationRequestMock.getClientID()).thenReturn(new ClientID("JUnit_client"));
        when(authenticationRequestMock.getRedirectionURI()).thenReturn(new URI("http://client.app/testing"));
        when(authenticationRequestMock.getState()).thenReturn(new State("stateValue"));
        when(authenticationRequestMock.getNonce()).thenReturn(new Nonce("nonceValue"));
        when(authenticationRequestMock.getScope()).thenReturn(Scope.parse("scope1 scope2"));

        when(httpServletRequestMock.getSession()).thenReturn(httpSessionMock);

        when(httpServletRequestMock.getHeader("User-Agent")).thenReturn("UserAgentValue");
        when(httpServletRequestMock.getRemoteAddr()).thenReturn("remoteAddressValue");

        when(urlUtilMock.determineRoot(httpServletRequestMock)).thenReturn("http://some.host/root");

        ClientInfo clientInfo = new ClientInfo();
        String idTokenSecret = "01234567890123456789012345678901234567890";
        clientInfo.setIdTokenSecret(idTokenSecret);
        when(clientInfoRetrieverMock.retrieveInfo("JUnit_client")).thenReturn(clientInfo);

        authenticationServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(stringArgumentCaptor.capture());

        String callbackURL = stringArgumentCaptor.getValue();
        assertThat(callbackURL).startsWith("http://client.app/testing?id_token=");
        assertThat(callbackURL).endsWith("&state=stateValue");

        String idToken = callbackURL.substring(35, callbackURL.indexOf('&'));

        SignedJWT jwt = SignedJWT.parse(idToken);
        jwt.verify(new MACVerifier(idTokenSecret));
        checkIdToken(IDTokenClaimsSet.parse(jwt.getJWTClaimsSet().toJSONObject().toJSONString()));

        verify(tokenStoreMock).addLoginFromClient(any(OctopusSSOUser.class), cookieTokenArgumentCaptor.capture(),
                userAgentArgumentCaptor.capture(), remoteHostArgumentCaptor.capture(), oidcStoreDataArgumentCaptor.capture());

        assertThat(cookieTokenArgumentCaptor.getValue()).isEqualTo("CookieTokenRememberMe");
        assertThat(userAgentArgumentCaptor.getValue()).isEqualTo("UserAgentValue");
        assertThat(remoteHostArgumentCaptor.getValue()).isEqualTo("remoteAddressValue");

        assertThat(oidcStoreDataArgumentCaptor.getValue().getAuthorizationCode()).isNull();
        assertThat(oidcStoreDataArgumentCaptor.getValue().getAccessToken()).isNotNull();
        assertThat(oidcStoreDataArgumentCaptor.getValue().getScope().toStringList()).containsExactly("scope1", "scope2");
        assertThat(oidcStoreDataArgumentCaptor.getValue().getClientId().getValue()).isEqualTo("JUnit_client");

        IDTokenClaimsSet claimsSet = oidcStoreDataArgumentCaptor.getValue().getIdTokenClaimsSet();

        checkIdToken(claimsSet);

        verify(httpSessionMock).invalidate();
    }

    @Test
    public void doGet_happyCase_ImplicitFlow() throws ServletException, IOException, ParseException, URISyntaxException, java.text.ParseException, JOSEException {
        OctopusSSOUser ssoUser = new OctopusSSOUser();
        ssoUser.setFullName("JUnit test");
        ssoUser.setCookieToken("CookieTokenRememberMe");
        when(ssoProducerBeanMock.getOctopusSSOUser()).thenReturn(ssoUser);

        when(timeUtilMock.addSecondsToDate(anyLong(), any(Date.class))).thenReturn(new Date());
        when(ssoServerConfiguration.getOIDCTokenLength()).thenReturn(48);

        when(httpServletRequestMock.getAttribute(AbstractRequest.class.getName())).thenReturn(authenticationRequestMock);
        when(authenticationRequestMock.getResponseType()).thenReturn(ResponseType.parse("id_token token"));
        when(authenticationRequestMock.getClientID()).thenReturn(new ClientID("JUnit_client"));
        when(authenticationRequestMock.getRedirectionURI()).thenReturn(new URI("http://client.app/testing"));
        when(authenticationRequestMock.getState()).thenReturn(new State("stateValue"));
        when(authenticationRequestMock.getNonce()).thenReturn(new Nonce("nonceValue"));
        when(authenticationRequestMock.getScope()).thenReturn(Scope.parse("scope1 scope2"));

        when(httpServletRequestMock.getSession()).thenReturn(httpSessionMock);

        when(httpServletRequestMock.getHeader("User-Agent")).thenReturn("UserAgentValue");
        when(httpServletRequestMock.getRemoteAddr()).thenReturn("remoteAddressValue");

        when(urlUtilMock.determineRoot(httpServletRequestMock)).thenReturn("http://some.host/root");

        ClientInfo clientInfo = new ClientInfo();
        String idTokenSecret = "01234567890123456789012345678901234567890";
        clientInfo.setIdTokenSecret(idTokenSecret);
        when(clientInfoRetrieverMock.retrieveInfo("JUnit_client")).thenReturn(clientInfo);

        authenticationServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(stringArgumentCaptor.capture());

        String callbackURL = stringArgumentCaptor.getValue();
        assertThat(callbackURL).startsWith("http://client.app/testing?access_token=");

        String query = callbackURL.substring(callbackURL.indexOf('?') + 1);
        Map<String, String> parameters = URLUtils.parseParameters(query);

        assertThat(parameters.keySet()).containsOnly("access_token", "id_token", "state", "token_type", "scope");

        assertThat(parameters.get("state")).isEqualTo("stateValue");
        assertThat(parameters.get("token_type")).isEqualTo("Bearer");

        byte[] bytes = Base64.decode(parameters.get("access_token"));
        assertThat(bytes.length >= 45 && bytes.length <= 48).isTrue(); // Don't know why the actual length isn't 48


        String idToken = parameters.get("id_token");
        SignedJWT jwt = SignedJWT.parse(idToken);
        jwt.verify(new MACVerifier(idTokenSecret));
        checkIdToken(IDTokenClaimsSet.parse(jwt.getJWTClaimsSet().toJSONObject().toJSONString()));

        verify(tokenStoreMock).addLoginFromClient(any(OctopusSSOUser.class), cookieTokenArgumentCaptor.capture(),
                userAgentArgumentCaptor.capture(), remoteHostArgumentCaptor.capture(), oidcStoreDataArgumentCaptor.capture());

        assertThat(cookieTokenArgumentCaptor.getValue()).isEqualTo("CookieTokenRememberMe");
        assertThat(userAgentArgumentCaptor.getValue()).isEqualTo("UserAgentValue");
        assertThat(remoteHostArgumentCaptor.getValue()).isEqualTo("remoteAddressValue");

        assertThat(oidcStoreDataArgumentCaptor.getValue().getAuthorizationCode()).isNull();
        assertThat(oidcStoreDataArgumentCaptor.getValue().getAccessToken().getValue()).isEqualTo(parameters.get("access_token"));
        assertThat(oidcStoreDataArgumentCaptor.getValue().getScope().toStringList()).containsExactly("scope1", "scope2");
        assertThat(oidcStoreDataArgumentCaptor.getValue().getClientId().getValue()).isEqualTo("JUnit_client");

        IDTokenClaimsSet claimsSet = oidcStoreDataArgumentCaptor.getValue().getIdTokenClaimsSet();

        checkIdToken(claimsSet);

        verify(httpSessionMock).invalidate();
    }

}