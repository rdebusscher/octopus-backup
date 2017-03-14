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
import be.c4j.ee.security.sso.SSOFlow;
import be.c4j.ee.security.sso.client.OpenIdVariableClientData;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import net.jadler.Jadler;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
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
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

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
    private PrintWriter printWriterMock;

    @Mock
    private OctopusConfig octopusConfigMock;

    @Mock
    private OctopusSSOClientConfiguration clientConfigurationMock;

    @Captor
    private ArgumentCaptor<String> stringArgumentCaptor;

    @InjectMocks
    private SSOCallbackServlet callbackServlet;

    @Before
    public void setUp() {
        Jadler.initJadler();
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

        when(httpServletResponseMock.getWriter()).thenReturn(printWriterMock);

        when(httpServletRequestMock.getQueryString()).thenReturn("error_description=Invalid+request%3A+Missing+%22client_id%22+parameter&state=stateCode&error=invalid_request");

        callbackServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(printWriterMock).println(stringArgumentCaptor.capture());
        assertThat(stringArgumentCaptor.getValue()).isEqualTo("invalid_request : Invalid request: Missing \"client_id\" parameter");
    }

    @Test
    public void doGet_InvalidRequest_NoState() throws ServletException, IOException {
        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);
        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");
        when(httpSessionMock.getAttribute(OpenIdVariableClientData.class.getName())).thenReturn(clientData);

        when(httpServletResponseMock.getWriter()).thenReturn(printWriterMock);

        when(httpServletRequestMock.getQueryString()).thenReturn("blablabla=wrong");

        callbackServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(printWriterMock).println(stringArgumentCaptor.capture());
        assertThat(stringArgumentCaptor.getValue()).isEqualTo("OCT-SSO-CLIENT-011 : Request has an invalid 'state' value");
    }


    @Test
    public void doGet_InvalidRequest_MissingSession() throws ServletException, IOException {
        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);

        when(httpSessionMock.getAttribute(OpenIdVariableClientData.class.getName())).thenReturn(null);

        when(httpServletResponseMock.getWriter()).thenReturn(printWriterMock);

        callbackServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(printWriterMock).println(stringArgumentCaptor.capture());
        assertThat(stringArgumentCaptor.getValue()).isEqualTo("OCT-SSO-CLIENT-012 : Request did not originate from this session");
    }


    @Test
    public void doGet_WrongState() throws ServletException, IOException {
        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);
        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");
        when(httpSessionMock.getAttribute(OpenIdVariableClientData.class.getName())).thenReturn(clientData);

        when(httpServletResponseMock.getWriter()).thenReturn(printWriterMock);

        when(httpServletRequestMock.getQueryString()).thenReturn("code=TheAuthenticationCode&state=stateValue");

        callbackServlet.doGet(httpServletRequestMock, httpServletResponseMock);
        verify(printWriterMock).println(stringArgumentCaptor.capture());
        assertThat(stringArgumentCaptor.getValue()).isEqualTo("OCT-SSO-CLIENT-011 : Request has an invalid 'state' value");
    }


    @Test
    public void doGet_MissingAuthorizationCode() throws ServletException, IOException, ParseException {
        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);
        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");
        when(httpSessionMock.getAttribute(OpenIdVariableClientData.class.getName())).thenReturn(clientData);

        when(httpServletResponseMock.getWriter()).thenReturn(printWriterMock);

        List<Audience> audience = new ArrayList<Audience>();
        IDTokenClaimsSet tokenClaimsSet = new IDTokenClaimsSet(new Issuer("Issuer"), new Subject("subject"), audience, new Date(), new Date());
        String idToken = new PlainJWT(tokenClaimsSet.toJWTClaimsSet()).serialize();
        when(httpServletRequestMock.getQueryString()).thenReturn("id_token=" + idToken + "&state=" + clientData.getState().getValue());

        when(clientConfigurationMock.getSSOType()).thenReturn(SSOFlow.AUTHORIZATION_CODE);

        callbackServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(printWriterMock).println(stringArgumentCaptor.capture());
        assertThat(stringArgumentCaptor.getValue()).isEqualTo("OCT-SSO-CLIENT-013 : Missing Authorization code");
    }

    //@Test
    @Ignore // FIXME
    public void doGet_ValidAuthenticationToken() throws ServletException, IOException {
        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);
        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");
        when(httpSessionMock.getAttribute(OpenIdVariableClientData.class.getName())).thenReturn(clientData);

        when(httpServletResponseMock.getWriter()).thenReturn(printWriterMock);


        when(httpServletRequestMock.getQueryString()).thenReturn("code=TheAuthenticationCode&state=" + clientData.getState().getValue());

        when(clientConfigurationMock.getSSOType()).thenReturn(SSOFlow.AUTHORIZATION_CODE);
        when(clientConfigurationMock.getSSOClientId()).thenReturn("JUnit_client");
        when(clientConfigurationMock.getSSOClientSecret()).thenReturn("0123456789012345678901234567890");
        when(clientConfigurationMock.getTokenEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc");

        /*
        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/oidc")
                .havingBody(isEmptyOrNullString())
                .havingHeaderEqualTo("Accept", "application/json")
                .respond()
                .withDelay(2, SECONDS)
                .withStatus(200)
                .withBody("{\\"account\\":{\\"id\\" : 1}}")
                .withEncoding(Charset.forName("UTF-8"))
                .withContentType("application/json; charset=UTF-8");
*/
        callbackServlet.doGet(httpServletRequestMock, httpServletResponseMock);
        verify(printWriterMock, never()).println(stringArgumentCaptor.capture());
    }

}