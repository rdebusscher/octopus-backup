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
package be.c4j.ee.security.sso.server.filter;

import be.c4j.ee.security.shiro.OctopusUserFilter;
import be.c4j.ee.security.sso.server.client.ClientInfo;
import be.c4j.ee.security.sso.server.client.ClientInfoRetriever;
import be.c4j.ee.security.sso.server.cookie.SSOHelper;
import be.c4j.test.util.BeanManagerFake;
import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class OIDCEndpointFilterTest {

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private ClientInfoRetriever clientInfoRetrieverMock;

    @Mock
    private SSOHelper ssoHelperMock;

    @Mock
    private Subject subjectMock;

    @Mock
    private PrintWriter printWriterMock;

    @Captor
    private ArgumentCaptor<AuthenticationRequest> authenticationRequestCapture;

    @Captor
    private ArgumentCaptor<String> stringCapture;

    @InjectMocks
    private OIDCEndpointFilter endpointFilter;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() {

        beanManagerFake = new BeanManagerFake();
        beanManagerFake.registerBean(clientInfoRetrieverMock, ClientInfoRetriever.class);
        beanManagerFake.registerBean(ssoHelperMock, SSOHelper.class);

        beanManagerFake.endRegistration();

        endpointFilter.init();
        endpointFilter.setUserFilter(new OctopusUserFilter());
    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void onPreHandle_authenticate_happyCase() throws Exception {
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/authenticate");
        when(httpServletRequestMock.getQueryString()).thenReturn("response_type=code&client_id=demo-clientId&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Foctopus%2Fsso%2FSSOCallback&scope=openid&state=stateCode&nonce=nonceCode");

        when(httpServletRequestMock.getContextPath()).thenReturn("/oidc");
        ThreadContext.bind(subjectMock);
        when(subjectMock.getPrincipal()).thenReturn(new Object());  // Anything will do as principal

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setOctopusClient(true);
        clientInfo.setCallbackURL("http://localhost:8080/sso-app2");
        when(clientInfoRetrieverMock.retrieveInfo("demo-clientId")).thenReturn(clientInfo);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, null, null);
        assertThat(data).isEqualTo(true);

        verify(httpServletRequestMock).setAttribute(stringCapture.capture(), authenticationRequestCapture.capture());

        assertThat(stringCapture.getValue()).isEqualTo(AbstractRequest.class.getName());
        assertThat(authenticationRequestCapture.getValue()).isInstanceOf(AuthenticationRequest.class);

        verify(ssoHelperMock).markAsSSOLogin(httpServletRequestMock, "demo-clientId");
    }

    @Test
    public void onPreHandle_authenticate_MissingClientId() throws Exception {
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/authenticate");
        when(httpServletRequestMock.getQueryString()).thenReturn("response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Foctopus%2Fsso%2FSSOCallback&scope=openid&state=stateCode&nonce=nonceCode");

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock, null);
        assertThat(data).isEqualTo(false);

        verify(httpServletResponseMock).sendRedirect(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("http://localhost:8080/sso-app2/octopus/sso/SSOCallback?error_description=Invalid+request%3A+Missing+%22client_id%22+parameter&state=stateCode&error=invalid_request");
        verifyNoMoreInteractions(ssoHelperMock);

    }

    @Test
    public void onPreHandle_authenticate_MissingClientId_NoValidRedirect() throws Exception {
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/authenticate");
        when(httpServletRequestMock.getQueryString()).thenReturn("response_type=code&redirect_uri=sso-app2&scope=openid&state=stateCode&nonce=nonceCode");

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock, null);
        assertThat(data).isEqualTo(false);

        verify(httpServletResponseMock).sendRedirect(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("sso-app2?error_description=Invalid+request%3A+Missing+%22client_id%22+parameter&state=stateCode&error=invalid_request");
        verifyNoMoreInteractions(ssoHelperMock);

    }

    @Test
    public void onPreHandle_authenticate_MissingRedirectURI() throws Exception {
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/authenticate");
        when(httpServletRequestMock.getQueryString()).thenReturn("response_type=code&client_id=demo-clientId&scope=openid&state=stateCode&nonce=nonceCode");

        when(httpServletResponseMock.getWriter()).thenReturn(printWriterMock);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock, null);
        assertThat(data).isEqualTo(false);

        verify(printWriterMock).println(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("Invalid request: Missing \"redirect_uri\" parameter");
    }

    @Test
    public void onPreHandle_authenticate_unknownClientId() throws Exception {
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/authenticate");
        when(httpServletRequestMock.getQueryString()).thenReturn("response_type=code&client_id=demo-clientId&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Foctopus%2Fsso%2FSSOCallback&scope=openid&state=stateCode&nonce=nonceCode");

        when(clientInfoRetrieverMock.retrieveInfo("demo-clientId")).thenReturn(null);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock, null);
        assertThat(data).isEqualTo(false);

        verify(httpServletResponseMock).sendRedirect(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("http://localhost:8080/sso-app2/octopus/sso/SSOCallback?error_description=Client+authentication+failed%3A+Unknown+%22client_id%22+parameter+value&state=stateCode&error=invalid_client");

        verify(httpServletRequestMock, never()).setAttribute(stringCapture.capture(), authenticationRequestCapture.capture());
        verifyNoMoreInteractions(ssoHelperMock);
    }

    @Test
    public void onPreHandle_authenticate_unknownRedirectURI() throws Exception {
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/authenticate");
        when(httpServletRequestMock.getQueryString()).thenReturn("response_type=code&client_id=demo-clientId&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Foctopus%2Fsso%2FSSOCallback&scope=openid&state=stateCode&nonce=nonceCode");

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setOctopusClient(true);
        clientInfo.setCallbackURL("http://localhost:8080/sso-app1");
        when(clientInfoRetrieverMock.retrieveInfo("demo-clientId")).thenReturn(clientInfo);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock, null);
        assertThat(data).isEqualTo(false);

        verify(httpServletResponseMock).sendRedirect(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("http://localhost:8080/sso-app2/octopus/sso/SSOCallback?error_description=Client+authentication+failed%3A+Unknown+%22redirect_uri%22+parameter+value&state=stateCode&error=invalid_client");

        verify(httpServletRequestMock, never()).setAttribute(stringCapture.capture(), authenticationRequestCapture.capture());
        verifyNoMoreInteractions(ssoHelperMock);
    }


}