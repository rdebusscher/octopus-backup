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
package be.c4j.ee.security.permission.filter;

import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.PermissionLookupFixture;
import be.c4j.ee.security.permission.StringPermissionLookupFixture;
import be.c4j.test.util.BeanManagerFake;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import java.util.List;

import static be.c4j.ee.security.interceptor.testclasses.TestPermission.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class NamedPermissionFilterTest {

    private NamedPermissionFilter filter;

    private BeanManagerFake beanManagerFake;

    @Mock
    private Subject subjectMock;

    @Captor
    private ArgumentCaptor<Permission> permissionArgumentCaptor;

    @Before
    public void setUp() {
        filter = new NamedPermissionFilter();

        beanManagerFake = new BeanManagerFake();

        ThreadContext.bind(subjectMock);
    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void isAccessAllowed_NamedTypeSafe_Allowed() throws Exception {

        PermissionLookupFixture.registerPermissionLookup(beanManagerFake);

        beanManagerFake.endRegistration();

        filter.init();  // Initialization of CDI beans

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(true);
        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{PERMISSION1.name()});
        assertThat(accessAllowed).isTrue();

        verify(subjectMock).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(NamedDomainPermission.class);

        Permission permission = permissionArgumentCaptor.getValue();
        assertThat(permission.toString()).isEqualTo("[permission]:[1]:[*]");
    }

    @Test
    public void isAccessAllowed_NamedTypeSafe_NotAllowed() throws Exception {

        PermissionLookupFixture.registerPermissionLookup(beanManagerFake);

        beanManagerFake.endRegistration();

        filter.init();  // Initialization of CDI beans

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(false);
        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{PERMISSION3.name()});

        assertThat(accessAllowed).isFalse();

        verify(subjectMock).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(NamedDomainPermission.class);

        Permission permission = permissionArgumentCaptor.getValue();
        assertThat(permission.toString()).isEqualTo("[permission]:[3]:[*]");

    }

    @Test
    public void isAccessAllowed_NamedTypeSafe_Multiple_Found() throws Exception {

        PermissionLookupFixture.registerPermissionLookup(beanManagerFake);

        beanManagerFake.endRegistration();

        filter.init();  // Initialization of CDI beans

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(true);
        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{PERMISSION1.name(), PERMISSION2.name()});
        assertThat(accessAllowed).isTrue();

        verify(subjectMock, times(2)).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(NamedDomainPermission.class);

        List<Permission> allValues = permissionArgumentCaptor.getAllValues();
        assertThat(allValues).hasSize(2);
        Permission permission = allValues.get(0);
        assertThat(permission.toString()).isEqualTo("[permission]:[1]:[*]");

        permission = allValues.get(1);
        assertThat(permission.toString()).isEqualTo("[permission]:[2]:[*]");
    }

    @Test
    public void isAccessAllowed_NamedTypeSafe_Multiple_OneNotAllowed() throws Exception {

        PermissionLookupFixture.registerPermissionLookup(beanManagerFake);

        beanManagerFake.endRegistration();

        filter.init();  // Initialization of CDI beans

        when(subjectMock.isPermitted(any(Permission.class))).thenAnswer(new Answer<Object>() {
            @Override
            public Boolean answer(InvocationOnMock invocation) throws Throwable {
                Permission permission = (Permission) invocation.getArguments()[0];
                return "[permission]:[1]:[*]".equals(permission.toString());
            }
        });

        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{PERMISSION1.name(), PERMISSION2.name()});
        assertThat(accessAllowed).isFalse();

        verify(subjectMock, times(2)).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(NamedDomainPermission.class);

        List<Permission> allValues = permissionArgumentCaptor.getAllValues();
        assertThat(allValues).hasSize(2);
        NamedDomainPermission permission = (NamedDomainPermission) allValues.get(0);
        assertThat(permission.toString()).isEqualTo("[permission]:[1]:[*]");

        permission = (NamedDomainPermission) allValues.get(1);
        assertThat(permission.toString()).isEqualTo("[permission]:[2]:[*]");
    }

    @Test
    public void isAccessAllowed_NamedStrings_Allowed() throws Exception {

        StringPermissionLookupFixture.registerLookup(beanManagerFake);

        beanManagerFake.endRegistration();

        filter.init();  // Initialization of CDI beans

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(true);
        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{"permission1"});
        assertThat(accessAllowed).isTrue();

        verify(subjectMock).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(NamedDomainPermission.class);

        Permission permission = permissionArgumentCaptor.getValue();
        assertThat(permission.toString()).isEqualTo("[spermission]:[1]:[*]");
    }

    @Test
    public void isAccessAllowed_NamedString_NotAllowed() throws Exception {

        StringPermissionLookupFixture.registerLookup(beanManagerFake);

        beanManagerFake.endRegistration();

        filter.init();  // Initialization of CDI beans

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(false);
        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{"permission3"});

        assertThat(accessAllowed).isFalse();

        verify(subjectMock).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(NamedDomainPermission.class);

        Permission permission = permissionArgumentCaptor.getValue();
        assertThat(permission.toString()).isEqualTo("[spermission]:[3]:[*]");

    }

    @Test
    public void isAccessAllowed_NamedString_Multiple_Found() throws Exception {

        StringPermissionLookupFixture.registerLookup(beanManagerFake);

        beanManagerFake.endRegistration();

        filter.init();  // Initialization of CDI beans

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(true);
        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{"permission1", "permission2"});
        assertThat(accessAllowed).isTrue();

        verify(subjectMock, times(2)).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(NamedDomainPermission.class);

        List<Permission> allValues = permissionArgumentCaptor.getAllValues();
        assertThat(allValues).hasSize(2);
        Permission permission = allValues.get(0);
        assertThat(permission.toString()).isEqualTo("[spermission]:[1]:[*]");

        permission = allValues.get(1);
        assertThat(permission.toString()).isEqualTo("[spermission]:[2]:[*]");
    }

    @Test
    public void isAccessAllowed_NamedString_Multiple_OneNotAllowed() throws Exception {

        StringPermissionLookupFixture.registerLookup(beanManagerFake);

        beanManagerFake.endRegistration();

        filter.init();  // Initialization of CDI beans

        when(subjectMock.isPermitted(any(Permission.class))).thenAnswer(new Answer<Object>() {
            @Override
            public Boolean answer(InvocationOnMock invocation) throws Throwable {
                Permission permission = (Permission) invocation.getArguments()[0];
                return "[spermission]:[1]:[*]".equals(permission.toString());
            }
        });

        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{"permission1", "permission2"});
        assertThat(accessAllowed).isFalse();

        verify(subjectMock, times(2)).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(NamedDomainPermission.class);

        List<Permission> allValues = permissionArgumentCaptor.getAllValues();
        assertThat(allValues).hasSize(2);
        NamedDomainPermission permission = (NamedDomainPermission) allValues.get(0);
        assertThat(permission.toString()).isEqualTo("[spermission]:[1]:[*]");

        permission = (NamedDomainPermission) allValues.get(1);
        assertThat(permission.toString()).isEqualTo("[spermission]:[2]:[*]");
    }

    @Test
    public void isAccessAllowed_Wildcard_Allowed() throws Exception {

        beanManagerFake.endRegistration();

        filter.init();  // Initialization of CDI beans

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(true);
        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{"junit:permission:1"});
        assertThat(accessAllowed).isTrue();

        verify(subjectMock).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(WildcardPermission.class);

        Permission permission = permissionArgumentCaptor.getValue();
        assertThat(permission.toString()).isEqualTo("[junit]:[permission]:[1]");
    }

    @Test
    public void isAccessAllowed_Simple_Allowed() throws Exception {

        beanManagerFake.endRegistration();

        filter.init();  // Initialization of CDI beans

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(false);
        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{"junit"});
        assertThat(accessAllowed).isFalse();

        verify(subjectMock).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(WildcardPermission.class);

        Permission permission = permissionArgumentCaptor.getValue();
        assertThat(permission.toString()).isEqualTo("[junit]:[*]:[*]");
    }

}