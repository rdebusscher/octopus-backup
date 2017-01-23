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
 *
 */
package be.c4j.ee.security.sso.server.filter;

import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.encryption.SSODataEncryptionHandler;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;
import be.c4j.ee.security.token.IncorrectDataToken;
import org.apache.shiro.authc.AuthenticationToken;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class SSOAuthenticatingFilterTest {

    private static final String REAL_TOKEN = "realToken";
    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private SSODataEncryptionHandler ssoDataEncryptionHandlerMock;

    @Mock
    private SSOTokenStore tokenStore;

    @InjectMocks
    private SSOAuthenticatingFilter ssoAuthenticatingFilter;

    @Test
    public void createToken_missingAuthenticationHeader() throws Exception {
        when(ssoDataEncryptionHandlerMock.requiresApiKey()).thenReturn(Boolean.FALSE);

        AuthenticationToken token = ssoAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);

        assertThat(token).isInstanceOf(IncorrectDataToken.class);
        IncorrectDataToken incorrect = (IncorrectDataToken) token;
        assertThat(incorrect.toString()).containsOnlyOnce("Authorization header required");
    }

    @Test
    public void createToken_missingXApiKey() throws Exception {
        when(ssoDataEncryptionHandlerMock.requiresApiKey()).thenReturn(Boolean.TRUE);

        AuthenticationToken token = ssoAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);

        assertThat(token).isInstanceOf(IncorrectDataToken.class);
        IncorrectDataToken incorrect = (IncorrectDataToken) token;
        assertThat(incorrect.toString()).containsOnlyOnce("x-api-key header required");
    }

    @Test
    public void createToken_IncorrectAuthorizationHeader() throws Exception {
        when(ssoDataEncryptionHandlerMock.requiresApiKey()).thenReturn(Boolean.FALSE);
        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("JUnit");

        AuthenticationToken token = ssoAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);

        assertThat(token).isInstanceOf(IncorrectDataToken.class);
        IncorrectDataToken incorrect = (IncorrectDataToken) token;
        assertThat(incorrect.toString()).containsOnlyOnce("Authorization header value incorrect");
    }

    @Test
    public void createToken_IncorrectAuthorizationHeader2() throws Exception {
        when(ssoDataEncryptionHandlerMock.requiresApiKey()).thenReturn(Boolean.FALSE);
        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("Part1 Part2");

        AuthenticationToken token = ssoAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);

        assertThat(token).isInstanceOf(IncorrectDataToken.class);
        IncorrectDataToken incorrect = (IncorrectDataToken) token;
        assertThat(incorrect.toString()).containsOnlyOnce("Authorization header value must start with Bearer");
    }

    @Test
    public void createToken_tokenInvalid() throws Exception {
        when(ssoDataEncryptionHandlerMock.requiresApiKey()).thenReturn(Boolean.FALSE);
        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("Bearer token");
        when(ssoDataEncryptionHandlerMock.validate(null, "token")).thenReturn(false);

        AuthenticationToken token = ssoAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);

        assertThat(token).isInstanceOf(IncorrectDataToken.class);
        IncorrectDataToken incorrect = (IncorrectDataToken) token;
        assertThat(incorrect.toString()).containsOnlyOnce("Authentication failed");
    }

    @Test
    public void createToken_realTokenNotActive() throws Exception {
        when(ssoDataEncryptionHandlerMock.requiresApiKey()).thenReturn(Boolean.FALSE);
        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("Bearer token");
        when(ssoDataEncryptionHandlerMock.validate(null, "token")).thenReturn(true);
        when(ssoDataEncryptionHandlerMock.decryptData("token", null)).thenReturn(null);

        AuthenticationToken token = ssoAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);

        assertThat(token).isInstanceOf(IncorrectDataToken.class);
        IncorrectDataToken incorrect = (IncorrectDataToken) token;
        assertThat(incorrect.toString()).containsOnlyOnce("Authentication failed");
    }

    @Test
    public void createToken() throws Exception {
        when(ssoDataEncryptionHandlerMock.requiresApiKey()).thenReturn(Boolean.FALSE);
        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("Bearer token");
        when(ssoDataEncryptionHandlerMock.validate(null, "token")).thenReturn(true);
        when(ssoDataEncryptionHandlerMock.decryptData("token", null)).thenReturn(REAL_TOKEN);
        OctopusSSOUser user = new OctopusSSOUser();
        when(tokenStore.getUser(REAL_TOKEN)).thenReturn(user);

        AuthenticationToken token = ssoAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);

        assertThat(token).isNotExactlyInstanceOf(IncorrectDataToken.class);
        assertThat(token).isSameAs(user);
    }

}