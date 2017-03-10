package be.c4j.ee.security.sso.client;

import be.c4j.ee.security.sso.SSOFlow;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import be.c4j.ee.security.util.URLUtil;
import be.c4j.test.util.BeanManagerFake;
import be.c4j.util.ReflectionUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

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
    private HttpSession httpSessionMock;

    @InjectMocks
    private SSOOctopusUserFilter userFilter;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean(octopusSSOClientConfigurationMock, OctopusSSOClientConfiguration.class);
        beanManagerFake.registerBean(urlUtilMock, URLUtil.class);
        beanManagerFake.endRegistration();

        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);
        when(urlUtilMock.determineRoot(any(HttpServletRequest.class))).thenReturn("http://client.app/base");

        userFilter.init();
        userFilter.prepareLoginURL(httpServletRequestMock, null);
    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }


    @Test
    public void getLoginUrl() throws IllegalAccessException, NoSuchFieldException {

        when(octopusSSOClientConfigurationMock.getSSOClientId()).thenReturn("clientId");
        when(octopusSSOClientConfigurationMock.getSSOType()).thenReturn(SSOFlow.AUTHORIZATION_CODE);
        when(octopusSSOClientConfigurationMock.getSSOScopes()).thenReturn("");

        ReflectionUtil.setFieldValue(userFilter, "loginUrl", "http://sso.server.org/root");
        String loginUrl = userFilter.getLoginUrl();
        assertThat(loginUrl).startsWith("http://sso.server.org/root?response_type=code&client_id=clientId&redirect_uri=http%3A%2F%2Fclient.app%2Fbase%2Foctopus%2Fsso%2FSSOCallback&scope=openid+octopus&");
        assertThat(loginUrl).contains("&state=");
        assertThat(loginUrl).contains("&nonce=");
    }

}