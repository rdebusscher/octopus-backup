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
package be.c4j.ee.security.realm.event;

import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.util.ThreadContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthorizationCacheHolderTest {

    @Mock
    private RealmSecurityManager securityManagerMock;

    @Mock
    private AuthorizingRealm authorizingRealmMock;

    @Mock
    private Cache cacheMock;

    private AuthorizationCacheHolder authorizationCacheHolder;

    @Before
    public void setup() {
        authorizationCacheHolder = new AuthorizationCacheHolder();
        ThreadContext.bind(securityManagerMock);

        Collection<Realm> realms = new ArrayList<Realm>();
        realms.add(authorizingRealmMock);
        when(securityManagerMock.getRealms()).thenReturn(realms);

        when(authorizingRealmMock.getAuthorizationCache()).thenReturn(cacheMock);
    }

    @Test
    public void clearCache() {
        UserPrincipal userPrincipal = new UserPrincipal("id", "userName", "name");

        ClearAuthorizationCacheEvent clearEvent = new ClearAuthorizationCacheEvent(userPrincipal);

        Set keys = new HashSet();
        keys.add(new UserPrincipal("otherId", "otherName", "name")); // Cache contains multiple entries
        keys.add(userPrincipal);

        when(cacheMock.keys()).thenReturn(keys);

        authorizationCacheHolder.clearCache(clearEvent);

        verify(cacheMock).remove(userPrincipal);
        verify(cacheMock, never()).clear();
    }

    @Test
    public void clearCache_noCacheEntryAvailable() {

        UserPrincipal userPrincipal = new UserPrincipal("id", "userName", "name");

        ClearAuthorizationCacheEvent clearEvent = new ClearAuthorizationCacheEvent(userPrincipal);

        Set keys = new HashSet();
        keys.add(new UserPrincipal("otherId", "otherName", "name")); // Cache contains multiple entries

        when(cacheMock.keys()).thenReturn(keys);

        authorizationCacheHolder.clearCache(clearEvent);

        verify(cacheMock, never()).remove(any(Object.class));
        verify(cacheMock, never()).clear();

    }

    @Test
    public void clearCache_allUsers() {

        ClearAuthorizationCacheEvent clearEvent = new ClearAuthorizationCacheEvent(null);

        authorizationCacheHolder.clearCache(clearEvent);

        verify(cacheMock, never()).remove(any(Object.class));
        verify(cacheMock).clear();

    }
}