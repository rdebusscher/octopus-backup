package be.c4j.ee.security.credentials.authentication.oauth2.info;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2ProviderMetaData;
import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.test.util.BeanManagerFake;
import com.github.scribejava.core.model.Token;
import org.apache.shiro.authz.UnauthenticatedException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.WebApplicationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class UserControllerTest {

    private static final String TOKEN = "TheToken";
    private static final String PROVIDER = "TheProvider";

    @Mock
    private ExternalInternalIdMapper externalInternalIdMapperMock;

    @Mock
    private UserPrincipal userPrincipalMock;

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private OAuth2ProviderMetaData oAuth2ProviderMetaDataMock;

    @Mock
    private OAuth2InfoProvider oAuth2InfoProviderMock;

    @InjectMocks
    private UserController controller;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean(oAuth2ProviderMetaDataMock, OAuth2ProviderMetaData.class);
    }

    @After
    public void teardown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void getUserInfo() {

        beanManagerFake.endRegistration();

        controller.init();

        when(oAuth2ProviderMetaDataMock.getName()).thenReturn(PROVIDER);
        when(oAuth2ProviderMetaDataMock.getInfoProvider()).thenReturn(oAuth2InfoProviderMock);

        final OAuth2User oauth2User = new OAuth2User();

        when(oAuth2InfoProviderMock.retrieveUserInfo(any(Token.class), any(HttpServletRequest.class)))
                .thenAnswer(new Answer<OAuth2User>() {
                    @Override
                    public OAuth2User answer(InvocationOnMock invocation) throws Throwable {
                        Token token = (Token) invocation.getArguments()[0];
                        if (TOKEN.equals(token.getToken())) {
                            return oauth2User;
                        }
                        return null;
                    }
                });

        OAuth2User userInfo = controller.getUserInfo(TOKEN, PROVIDER, httpServletRequestMock);
        assertThat(userInfo).isEqualTo(oauth2User);
    }

    @Test(expected = WebApplicationException.class)
    public void getUserInfo_WrongToken() {

        beanManagerFake.endRegistration();

        controller.init();

        when(oAuth2ProviderMetaDataMock.getName()).thenReturn(PROVIDER);
        when(oAuth2ProviderMetaDataMock.getInfoProvider()).thenReturn(oAuth2InfoProviderMock);

        when(oAuth2InfoProviderMock.retrieveUserInfo(any(Token.class), any(HttpServletRequest.class)))
                .thenAnswer(new Answer<OAuth2User>() {
                    @Override
                    public OAuth2User answer(InvocationOnMock invocation) throws Throwable {
                        return null;
                    }
                });

        controller.getUserInfo(TOKEN, PROVIDER, httpServletRequestMock);
    }

    @Test(expected = WebApplicationException.class)
    public void getUserInfo_WrongToken2() {

        beanManagerFake.endRegistration();

        controller.init();

        when(oAuth2ProviderMetaDataMock.getName()).thenReturn(PROVIDER);
        when(oAuth2ProviderMetaDataMock.getInfoProvider()).thenReturn(oAuth2InfoProviderMock);

        when(oAuth2InfoProviderMock.retrieveUserInfo(any(Token.class), any(HttpServletRequest.class)))
                .thenThrow(new UnauthenticatedException());

        controller.getUserInfo(TOKEN, PROVIDER, httpServletRequestMock);
    }

}