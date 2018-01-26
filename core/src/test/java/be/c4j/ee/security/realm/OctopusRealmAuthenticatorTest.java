/*
 * Copyright 2014-2018 Rudy De Busscher
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
package be.c4j.ee.security.realm;

import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.test.util.ReflectionUtil;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static be.c4j.ee.security.OctopusConstants.AUTHORIZATION_INFO;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class OctopusRealmAuthenticatorTest {

    private OctopusRealmAuthenticator authenticator = new OctopusRealmAuthenticator();

    @Mock
    private AuthorizingRealm realmMock;

    @Mock
    private OctopusRealm octopusRealmMock;

    private AuthenticationToken token;

    @Before
    public void setup() {
        authenticator = new OctopusRealmAuthenticator();

        token = new UsernamePasswordToken();
    }

    @Test
    public void doSingleRealmAuthentication() {
        when(realmMock.supports(token)).thenReturn(true);
        AuthenticationInfo info = new SimpleAuthenticationInfo();
        when(realmMock.getAuthenticationInfo(token)).thenReturn(info);

        AuthenticationInfo result = authenticator.doSingleRealmAuthentication(realmMock, token);

        assertThat(result).isEqualTo(info);
    }

    @Test
    public void doSingleRealmAuthentication_authorizationInfo() throws NoSuchFieldException, IllegalAccessException {
        ReflectionUtil.setFieldValue(authenticator, "authorizationInfoRequired", Boolean.TRUE);

        when(realmMock.supports(token)).thenReturn(true);
        AuthenticationInfo info = new SimpleAuthenticationInfo();
        when(realmMock.getAuthenticationInfo(token)).thenReturn(info);

        AuthenticationInfo result = authenticator.doSingleRealmAuthentication(realmMock, token);

        assertThat(result).isEqualTo(info);
    }

    @Test
    public void doSingleRealmAuthentication_octopusRealm() {
        when(octopusRealmMock.supports(token)).thenReturn(true);
        UserPrincipal principal = new UserPrincipal("Id");
        AuthenticationInfo info = new SimpleAuthenticationInfo(principal, "PW", "JUnitRealm");
        when(octopusRealmMock.getAuthenticationInfo(token)).thenReturn(info);

        AuthenticationInfo result = authenticator.doSingleRealmAuthentication(octopusRealmMock, token);

        assertThat(result).isEqualTo(info);
    }

    @Test
    public void doSingleRealmAuthentication_octopusRealm_authorizationInfo() throws NoSuchFieldException, IllegalAccessException {
        ReflectionUtil.setFieldValue(authenticator, "authorizationInfoRequired", Boolean.TRUE);
        when(octopusRealmMock.supports(token)).thenReturn(true);

        UserPrincipal principal = new UserPrincipal("Id");
        AuthenticationInfo info = new SimpleAuthenticationInfo(principal, "PW", "JUnitRealm");
        when(octopusRealmMock.getAuthenticationInfo(token)).thenReturn(info);

        AuthorizationInfo authzInfo = new SimpleAuthorizationInfo();
        when(octopusRealmMock.doGetAuthorizationInfo(any(PrincipalCollection.class))).thenReturn(authzInfo);

        AuthenticationInfo result = authenticator.doSingleRealmAuthentication(octopusRealmMock, token);

        assertThat(result).isEqualTo(info);
        assertThat(result.getPrincipals().getPrimaryPrincipal()).isInstanceOf(UserPrincipal.class);

        UserPrincipal primaryPrincipal = (UserPrincipal) result.getPrincipals().getPrimaryPrincipal();
        assertThat(primaryPrincipal.getInfo()).containsKey(AUTHORIZATION_INFO);
        verify(octopusRealmMock).setAuthorizationCachedData(any(UserPrincipal.class), any(AuthorizationInfo.class));
        verify(octopusRealmMock).doGetAuthorizationInfo(any(PrincipalCollection.class));
    }

    @Test
    public void doSingleRealmAuthentication_octopusRealm_authorizationInfo_onPrincipal() throws NoSuchFieldException, IllegalAccessException {
        ReflectionUtil.setFieldValue(authenticator, "authorizationInfoRequired", Boolean.TRUE);
        when(octopusRealmMock.supports(token)).thenReturn(true);

        UserPrincipal principal = new UserPrincipal("Id");
        AuthenticationInfo info = new SimpleAuthenticationInfo(principal, "PW", "JUnitRealm");

        AuthorizationInfo authzInfo = new SimpleAuthorizationInfo();
        principal.addUserInfo(AUTHORIZATION_INFO, authzInfo);
        when(octopusRealmMock.getAuthenticationInfo(token)).thenReturn(info);

        AuthenticationInfo result = authenticator.doSingleRealmAuthentication(octopusRealmMock, token);

        assertThat(result).isEqualTo(info);
        assertThat(result.getPrincipals().getPrimaryPrincipal()).isInstanceOf(UserPrincipal.class);

        UserPrincipal primaryPrincipal = (UserPrincipal) result.getPrincipals().getPrimaryPrincipal();
        assertThat(primaryPrincipal.getInfo()).containsKey(AUTHORIZATION_INFO);
        verify(octopusRealmMock).setAuthorizationCachedData(any(UserPrincipal.class), any(AuthorizationInfo.class));
        verify(octopusRealmMock, never()).doGetAuthorizationInfo(any(PrincipalCollection.class));
    }

}