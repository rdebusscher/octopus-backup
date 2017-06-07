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
package be.c4j.ee.security.sso.client.access;

import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import be.c4j.ee.security.systemaccount.SystemAccountAuthenticationToken;
import be.c4j.ee.security.systemaccount.SystemAccountPrincipal;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.subject.Subject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class SSOAfterSuccessfulLoginHandlerTest {

    private static final String PERMISSION = "JUnit";

    @Mock
    private OctopusSSOClientConfiguration clientConfigurationMock;

    @Mock
    private Subject subjectMock;

    @InjectMocks
    private SSOAfterSuccessfulLoginHandler handler;

    @Test
    public void onSuccessfulLogin_hasAccessPermission() {
        AuthenticationToken token = new UsernamePasswordToken();

        when(clientConfigurationMock.getAccessPermission()).thenReturn(PERMISSION);
        handler.onSuccessfulLogin(token, null, subjectMock);

        verify(subjectMock).checkPermission(PERMISSION);
    }

    @Test
    public void onSuccessfulLogin_noAccessPermission() {
        AuthenticationToken token = new UsernamePasswordToken();

        handler.onSuccessfulLogin(token, null, subjectMock);
        verify(subjectMock, never()).checkPermission(PERMISSION);
    }

    @Test(expected = AuthorizationException.class)
    public void onSuccessfulLogin_hasNotAccessPermission() {
        AuthenticationToken token = new UsernamePasswordToken();

        Mockito.doThrow(new AuthorizationException())
                .when(subjectMock).checkPermission(PERMISSION);

        when(clientConfigurationMock.getAccessPermission()).thenReturn(PERMISSION);

        handler.onSuccessfulLogin(token, null, subjectMock);
    }

    @Test
    public void onSuccessfulLogin_SystemAccount() {
        AuthenticationToken token = new SystemAccountAuthenticationToken(new SystemAccountPrincipal("XXX"));

        handler.onSuccessfulLogin(token, null, subjectMock);

        verify(subjectMock, never()).checkPermission(PERMISSION);
    }

}