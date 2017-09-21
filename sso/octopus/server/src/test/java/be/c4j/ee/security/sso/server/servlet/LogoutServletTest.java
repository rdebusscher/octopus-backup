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

import be.c4j.ee.security.config.Debug;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.server.client.ClientInfo;
import be.c4j.ee.security.sso.server.client.ClientInfoRetriever;
import be.c4j.ee.security.sso.server.store.OIDCStoreData;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;
import be.c4j.ee.security.util.TimeUtil;
import be.c4j.test.util.BeanManagerFake;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.util.ThreadContext;
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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class LogoutServletTest {

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private ClientInfoRetriever clientInfoRetrieverMock;

    @Mock
    private OctopusSSOUser octopusSSOUserMock;

    @Mock
    private SSOTokenStore tokenStoreMock;

    @Mock
    private OctopusJSFConfig octopusJSFConfigMock;

    @Mock
    private OctopusConfig octopusConfigMock;

    @Mock
    private org.apache.shiro.subject.Subject subjectMock;

    @InjectMocks
    private LogoutServlet logoutServlet;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean(new TimeUtil(), TimeUtil.class);
        beanManagerFake.endRegistration();
    }

    @After
    public void teardown() {
        beanManagerFake.deregistration();
        TestLoggerFactory.clear();
    }

    @Test
    public void doGet() throws ServletException, IOException {
        TestLogger logger = TestLoggerFactory.getTestLogger(LogoutServlet.class);

        byte[] secret = defineSecret(256 / 8 + 1);
        String clientId = "clientId";

        when(httpServletRequestMock.getQueryString()).thenReturn(createJWT(clientId, secret, clientId));

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setClientSecret(Base64.encodeToString(secret));
        when(clientInfoRetrieverMock.retrieveInfo(clientId)).thenReturn(clientInfo);

        List<OIDCStoreData> storeDatas = new ArrayList<OIDCStoreData>();
        storeDatas.add(newOIDCStoreData("anotherClient"));
        storeDatas.add(newOIDCStoreData(clientId));
        when(tokenStoreMock.getLoggedInClients(octopusSSOUserMock)).thenReturn(storeDatas);

        clientInfo = new ClientInfo();
        clientInfo.setCallbackURL("other.client.org");
        clientInfo.setOctopusClient(true);
        when(clientInfoRetrieverMock.retrieveInfo("anotherClient")).thenReturn(clientInfo);

        when(octopusJSFConfigMock.getLogoutPage()).thenReturn("/logout.html");
        when(octopusConfigMock.showDebugFor()).thenReturn(new ArrayList<Debug>());
        ThreadContext.bind(subjectMock);

        logoutServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(tokenStoreMock).removeUser(octopusSSOUserMock);

        // This tests to see if we tried to send a logout request to the other client app.
        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.WARN);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).startsWith("Sending logout request to other.client.org/octopus/sso/SSOLogoutCallback?access_token=");

        assertThat(storeDatas).hasSize(1); // The doGet did a remove on the iterator effectively removing an entry!
    }

    @Test
    public void doGet_NoRequestParameters() throws ServletException, IOException {
        TestLogger logger = TestLoggerFactory.getTestLogger(LogoutServlet.class);

        when(httpServletRequestMock.getQueryString()).thenReturn("");

        logoutServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(tokenStoreMock, never()).removeUser(octopusSSOUserMock);

        assertThat(logger.getLoggingEvents()).isEmpty();
    }

    @Test
    public void doGet_unknownClientId() throws ServletException, IOException {
        TestLogger logger = TestLoggerFactory.getTestLogger(LogoutServlet.class);

        byte[] secret = defineSecret(256 / 8 + 1);
        String clientId = "clientId";

        when(httpServletRequestMock.getQueryString()).thenReturn(createJWT(clientId, secret, clientId));

        when(clientInfoRetrieverMock.retrieveInfo(clientId)).thenReturn(null);

        logoutServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(tokenStoreMock, never()).removeUser(octopusSSOUserMock);

        assertThat(logger.getLoggingEvents()).isEmpty();

    }

    @Test
    public void doGet_signatureVerificationIssue() throws ServletException, IOException {
        TestLogger logger = TestLoggerFactory.getTestLogger(LogoutServlet.class);

        byte[] secret = defineSecret(256 / 8 + 1);
        String clientId = "clientId";

        when(httpServletRequestMock.getQueryString()).thenReturn(createJWT(clientId, secret, clientId));

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setClientSecret(Base64.encodeToString(defineSecret(256 / 8 + 1)));  // We use another secret here
        when(clientInfoRetrieverMock.retrieveInfo(clientId)).thenReturn(clientInfo);

        logoutServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(tokenStoreMock, never()).removeUser(octopusSSOUserMock);

        assertThat(logger.getLoggingEvents()).isEmpty();
    }

    @Test
    public void doGet_wrongSubject() throws ServletException, IOException {
        TestLogger logger = TestLoggerFactory.getTestLogger(LogoutServlet.class);

        byte[] secret = defineSecret(256 / 8 + 1);
        String clientId = "clientId";

        when(httpServletRequestMock.getQueryString()).thenReturn(createJWT(clientId, secret, "wrongSubject"));

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setClientSecret(Base64.encodeToString(secret));
        when(clientInfoRetrieverMock.retrieveInfo(clientId)).thenReturn(clientInfo);

        logoutServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(tokenStoreMock, never()).removeUser(octopusSSOUserMock);

        assertThat(logger.getLoggingEvents()).isEmpty();
    }

    @Test
    public void doGet_timeOutExpirationDate() throws ServletException, IOException {
        TestLogger logger = TestLoggerFactory.getTestLogger(LogoutServlet.class);

        byte[] secret = defineSecret(256 / 8 + 1);
        String clientId = "clientId";

        when(httpServletRequestMock.getQueryString()).thenReturn(createJWT(clientId, secret, clientId));

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setClientSecret(Base64.encodeToString(secret));
        when(clientInfoRetrieverMock.retrieveInfo(clientId)).thenReturn(clientInfo);

        try {
            Thread.sleep(2100); // By default there is a sec timeToLive
        } catch (InterruptedException e) {
            fail(e.getMessage());
        }

        logoutServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(tokenStoreMock, never()).removeUser(octopusSSOUserMock);

        assertThat(logger.getLoggingEvents()).isEmpty();
    }


    private OIDCStoreData newOIDCStoreData(String clientId) {
        BearerAccessToken accessToken = new BearerAccessToken();
        OIDCStoreData result = new OIDCStoreData(accessToken);
        result.setClientId(new ClientID(clientId));
        return result;
    }

    private String createJWT(String clientId, byte[] secret, String subject) {
        SignedJWT result;

        TimeUtil timeUtil = new TimeUtil();
        Date iat = new Date();
        Date exp = timeUtil.addSecondsToDate(2, iat);
        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(new Issuer(clientId), new Subject(subject), new ArrayList<Audience>(), exp, iat);

        try {
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.HS256);
            headerBuilder.customParam("clientId", clientId);
            result = new SignedJWT(headerBuilder.build(), claimsSet.toJWTClaimsSet());

            result.sign(new MACSigner(secret));
        } catch (ParseException e) {
            throw new OctopusUnexpectedException(e);
        } catch (JOSEException e) {
            throw new OctopusUnexpectedException(e);
        }

        LogoutRequest logoutRequest = new LogoutRequest(null, result);
        return logoutRequest.toQueryString();

    }

    private byte[] defineSecret(int byteLength) {
        byte[] bytes = new byte[byteLength];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(bytes);

        return bytes;
    }

}