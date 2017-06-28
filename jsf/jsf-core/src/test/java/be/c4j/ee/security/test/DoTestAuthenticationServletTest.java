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
package be.c4j.ee.security.test;

import be.c4j.ee.security.OctopusConstants;
import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.ee.security.util.URLUtil;
import be.c4j.test.util.BeanManagerFake;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class DoTestAuthenticationServletTest {

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private OctopusJSFConfig octopusConfigMock;

    @Mock
    private URLUtil urlUtilMock;

    @InjectMocks
    private DoTestAuthenticationServlet servlet;

    @Captor
    private ArgumentCaptor<String> redirectCapture;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() throws IllegalAccessException {

        beanManagerFake = new BeanManagerFake();

    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void doGet_FirstRequest() throws ServletException, IOException {
        AuthenticatedPageInfo pageInfoMock = Mockito.mock(AuthenticatedPageInfo.class);

        beanManagerFake.registerBean(pageInfoMock, AuthenticatedPageInfo.class);

        beanManagerFake.endRegistration();

        StringBuffer requestURL = new StringBuffer("http://client.server/root/doTestAuthenticate");
        when(httpServletRequestMock.getRequestURL()).thenReturn(requestURL);
        when(octopusConfigMock.getLoginPage()).thenReturn("http://auth.server/security/octopus/authenticate");
        // The above simulates the SCS situation

        servlet.init();
        servlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(redirectCapture.capture());

        assertThat(redirectCapture.getValue()).isEqualTo("http://auth.server/security/octopus/testAuthentication?OctopusReferer=http%3A%2F%2Fclient.server%2Froot%2FdoTestAuthenticate");
        verifyNoMoreInteractions(urlUtilMock);
    }

    @Test
    public void doGet_FirstRequest_relativeLoginURL() throws ServletException, IOException {
        AuthenticatedPageInfo pageInfoMock = Mockito.mock(AuthenticatedPageInfo.class);

        beanManagerFake.registerBean(pageInfoMock, AuthenticatedPageInfo.class);

        beanManagerFake.endRegistration();

        StringBuffer requestURL = new StringBuffer("http://client.server/root/doTestAuthenticate");
        when(httpServletRequestMock.getRequestURL()).thenReturn(requestURL);
        when(octopusConfigMock.getLoginPage()).thenReturn("/login.xhtml");
        // This is the situation for a regular app, non SCS

        when(urlUtilMock.determineRoot(httpServletRequestMock)).thenReturn("http://client.server/root");

        servlet.init();
        servlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(redirectCapture.capture());

        assertThat(redirectCapture.getValue()).isEqualTo("http://client.server/root/octopus/testAuthentication?OctopusReferer=http%3A%2F%2Fclient.server%2Froot%2FdoTestAuthenticate");
        verify(urlUtilMock).determineRoot(httpServletRequestMock);
    }

    @Test
    public void doGet_FirstRequest_noRoot() throws ServletException, IOException {
        AuthenticatedPageInfo pageInfoMock = Mockito.mock(AuthenticatedPageInfo.class);

        beanManagerFake.registerBean(pageInfoMock, AuthenticatedPageInfo.class);

        beanManagerFake.endRegistration();

        StringBuffer requestURL = new StringBuffer("http://client.server/doTestAuthenticate");
        when(httpServletRequestMock.getRequestURL()).thenReturn(requestURL);
        when(octopusConfigMock.getLoginPage()).thenReturn("/login.xhtml");
        // This is the situation for a regular app, non SCS

        when(urlUtilMock.determineRoot(httpServletRequestMock)).thenReturn("http://client.server");

        servlet.init();
        servlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(redirectCapture.capture());

        assertThat(redirectCapture.getValue()).isEqualTo("http://client.server/octopus/testAuthentication?OctopusReferer=http%3A%2F%2Fclient.server%2FdoTestAuthenticate");
        verify(urlUtilMock).determineRoot(httpServletRequestMock);
    }

    @Test
    public void doGet_response_unauthenticated() throws ServletException, IOException {
        AuthenticatedPageInfo pageInfoMock = Mockito.mock(AuthenticatedPageInfo.class);

        beanManagerFake.registerBean(pageInfoMock, AuthenticatedPageInfo.class);

        beanManagerFake.endRegistration();

        when(httpServletRequestMock.getParameter(OctopusConstants.OCTOPUS_AUTHENTICATED)).thenReturn("false");
        when(pageInfoMock.getUnauthenticatedPage()).thenReturn("unauthenticated.xhtml");

        servlet.init();
        servlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(redirectCapture.capture());

        assertThat(redirectCapture.getValue()).isEqualTo("unauthenticated.xhtml");

    }

    @Test
    public void doGet_response_authenticated() throws ServletException, IOException {
        AuthenticatedPageInfo pageInfoMock = Mockito.mock(AuthenticatedPageInfo.class);

        beanManagerFake.registerBean(pageInfoMock, AuthenticatedPageInfo.class);

        beanManagerFake.endRegistration();

        when(httpServletRequestMock.getParameter(OctopusConstants.OCTOPUS_AUTHENTICATED)).thenReturn("true");
        when(pageInfoMock.getAuthenticatedPage()).thenReturn("authenticated.xhtml");

        servlet.init();
        servlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(redirectCapture.capture());

        assertThat(redirectCapture.getValue()).isEqualTo("authenticated.xhtml");

    }

}