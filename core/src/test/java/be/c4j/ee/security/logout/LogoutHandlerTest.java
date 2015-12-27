package be.c4j.ee.security.logout;

import be.c4j.ee.security.config.OctopusConfig;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import javax.faces.context.ExternalContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;


/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class LogoutHandlerTest {

    @Mock
    private ExternalContext externalContextMock;

    @Mock
    private OctopusConfig octopusConfigMock;

    @InjectMocks
    private LogoutHandler logoutHandler;

    @Test
    public void testGetLogoutPage() {
        when(externalContextMock.getRequestContextPath()).thenReturn("/demo");
        when(octopusConfigMock.getLogoutPage()).thenReturn("/");

        String logoutPage = logoutHandler.getLogoutPage(externalContextMock);

        assertThat(logoutPage).isEqualTo("/demo/");
    }

    @Test
    public void testGetLogoutPage_absolutePage() {
        when(externalContextMock.getRequestContextPath()).thenReturn("/demo");
        String logoutPage = "http://domain.com/logout";
        when(octopusConfigMock.getLogoutPage()).thenReturn(logoutPage);

        String result = logoutHandler.getLogoutPage(externalContextMock);

        assertThat(result).isEqualTo(logoutPage);
    }
}