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
package be.c4j.ee.security.sso.client;

import be.c4j.ee.security.sso.SSOFlow;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import be.c4j.ee.security.util.URLUtil;
import be.c4j.test.util.BeanManagerFake;
import be.c4j.test.util.ReflectionUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class SSOOctopusUserFilterTest {

    @Mock
    private OctopusSSOClientConfiguration octopusSSOClientConfigurationMock;

    @Mock
    private URLUtil urlUtilMock;

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private HttpSession httpSessionMock;

    @Mock
    private ClientCallbackHelper clientCallbackHelperMock;

    @Captor
    private ArgumentCaptor<String> stringArgumentCaptor;

    @InjectMocks
    private SSOOctopusUserFilter userFilter;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean(octopusSSOClientConfigurationMock, OctopusSSOClientConfiguration.class);
        beanManagerFake.registerBean(urlUtilMock, URLUtil.class);

        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);

        userFilter.init();
        userFilter.prepareLoginURL(httpServletRequestMock, null);
    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }


    @Test
    public void redirectToLogin() throws IllegalAccessException, NoSuchFieldException, IOException {
        beanManagerFake.endRegistration();

        when(octopusSSOClientConfigurationMock.getSSOClientId()).thenReturn("clientId");
        when(octopusSSOClientConfigurationMock.getSSOType()).thenReturn(SSOFlow.AUTHORIZATION_CODE);
        when(octopusSSOClientConfigurationMock.getSSOScopes()).thenReturn("");

        ReflectionUtil.setFieldValue(userFilter, "partialLoginURL", "http://sso.server.org/root");

        when(httpServletResponseMock.encodeRedirectURL(anyString())).thenAnswer(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {
                return invocation.getArgument(0);
            }
        });

        when(urlUtilMock.determineRoot(any(HttpServletRequest.class))).thenReturn("http://client.app/base");

        userFilter.redirectToLogin(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(stringArgumentCaptor.capture());

        String loginUrl = stringArgumentCaptor.getValue();

        assertThat(loginUrl).startsWith("http://sso.server.org/root?response_type=code&client_id=clientId&redirect_uri=http%3A%2F%2Fclient.app%2Fbase%2Foctopus%2Fsso%2FSSOCallback&scope=openid+octopus&");
        assertThat(loginUrl).contains("&state=");
        assertThat(loginUrl).contains("&nonce=");

        verify(urlUtilMock).determineRoot(any(HttpServletRequest.class));

    }

    @Test
    public void redirectToLogin_manualDetermined() throws IllegalAccessException, NoSuchFieldException, IOException {
        // TODO Doesn't work. why ?
        beanManagerFake.registerBean(clientCallbackHelperMock, ClientCallbackHelper.class);
        beanManagerFake.endRegistration();
        ReflectionUtil.injectDependencies(userFilter, clientCallbackHelperMock);

        when(octopusSSOClientConfigurationMock.getSSOClientId()).thenReturn("clientId");
        when(octopusSSOClientConfigurationMock.getSSOType()).thenReturn(SSOFlow.AUTHORIZATION_CODE);
        when(octopusSSOClientConfigurationMock.getSSOScopes()).thenReturn("");

        ReflectionUtil.setFieldValue(userFilter, "partialLoginURL", "http://sso.server.org/root");

        when(httpServletResponseMock.encodeRedirectURL(anyString())).thenAnswer(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {
                return invocation.getArgument(0);
            }
        });

        when(clientCallbackHelperMock.determineCallbackRoot(any(HttpServletRequest.class))).thenReturn("http://manual.url/root");

        userFilter.redirectToLogin(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(stringArgumentCaptor.capture());

        String loginUrl = stringArgumentCaptor.getValue();

        assertThat(loginUrl).startsWith("http://sso.server.org/root?response_type=code&client_id=clientId&redirect_uri=http%3A%2F%2Fmanual.url%2Froot%2Foctopus%2Fsso%2FSSOCallback&scope=openid+octopus&");
        assertThat(loginUrl).contains("&state=");
        assertThat(loginUrl).contains("&nonce=");

        verify(urlUtilMock, never()).determineRoot(any(HttpServletRequest.class));

    }

}