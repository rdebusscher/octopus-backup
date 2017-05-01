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
import be.c4j.test.util.ReflectionUtil;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.RedirectView;
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
import java.net.URLEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class TestAuthenticationServletTest {

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private Subject subjectMock;

    @Captor
    private ArgumentCaptor<String> redirectCapture;

    private TestAuthenticationServlet servlet;

    @Before
    public void setup() throws IllegalAccessException {
        servlet = new TestAuthenticationServlet();
        ReflectionUtil.injectDependencies(servlet, subjectMock);
    }

    @Test
    public void doGet_authenticated() throws ServletException, IOException {
        String encodedValue = URLEncoder.encode("http://some.server/root/doTest", RedirectView.DEFAULT_ENCODING_SCHEME);
        when(httpServletRequestMock.getParameter(OctopusConstants.OCTOPUS_REFERER)).thenReturn(encodedValue);

        when(subjectMock.isAuthenticated()).thenReturn(true);

        servlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(redirectCapture.capture());

        assertThat(redirectCapture.getValue()).isEqualTo("http://some.server/root/doTest?OctopusAuthenticated=true");
    }

    @Test
    public void doGet_unauthenticated() throws ServletException, IOException {
        String encodedValue = URLEncoder.encode("http://some.server/root/doTest", RedirectView.DEFAULT_ENCODING_SCHEME);
        when(httpServletRequestMock.getParameter(OctopusConstants.OCTOPUS_REFERER)).thenReturn(encodedValue);

        when(subjectMock.isAuthenticated()).thenReturn(false);

        servlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(redirectCapture.capture());

        assertThat(redirectCapture.getValue()).isEqualTo("http://some.server/root/doTest?OctopusAuthenticated=false");
    }

    @Test
    public void doGet_NoParameter() throws ServletException, IOException {
        String encodedValue = URLEncoder.encode("http://some.server/root/doTest", RedirectView.DEFAULT_ENCODING_SCHEME);
        when(httpServletRequestMock.getParameter(OctopusConstants.OCTOPUS_REFERER)).thenReturn(null);

        servlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendError(anyInt(), redirectCapture.capture());

        assertThat(redirectCapture.getValue()).isEqualTo("Missing query parameter");
    }

}