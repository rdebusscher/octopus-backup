package be.c4j.ee.security.test;

import be.c4j.ee.security.OctopusConstants;
import be.c4j.ee.security.config.OctopusJSFConfig;
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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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

        servlet.init();
        servlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(redirectCapture.capture());

        assertThat(redirectCapture.getValue()).isEqualTo("http://auth.server/security/testAuthentication?OctopusReferer=http%3A%2F%2Fclient.server%2Froot%2FdoTestAuthenticate");

    }

    @Test
    public void doGet_response_unauthenticated() throws ServletException, IOException {
        AuthenticatedPageInfo pageInfoMock = Mockito.mock(AuthenticatedPageInfo.class);

        beanManagerFake.registerBean(pageInfoMock, AuthenticatedPageInfo.class);

        beanManagerFake.endRegistration();

        StringBuffer requestURL = new StringBuffer("http://client.server/root/doTestAuthenticate");
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

        StringBuffer requestURL = new StringBuffer("http://client.server/root/doTestAuthenticate");
        when(httpServletRequestMock.getParameter(OctopusConstants.OCTOPUS_AUTHENTICATED)).thenReturn("true");
        when(pageInfoMock.getAuthenticatedPage()).thenReturn("authenticated.xhtml");

        servlet.init();
        servlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(redirectCapture.capture());

        assertThat(redirectCapture.getValue()).isEqualTo("authenticated.xhtml");

    }

}