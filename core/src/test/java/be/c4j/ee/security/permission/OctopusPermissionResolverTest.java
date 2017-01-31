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
package be.c4j.ee.security.permission;

import be.c4j.test.util.BeanManagerFake;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class OctopusPermissionResolverTest {

    private OctopusPermissionResolver permissionResolver;

    private BeanManagerFake beanManagerFake;

    @Mock
    private StringPermissionLookup stringPermissionLookupMock;

    @Mock
    private PermissionLookup permissionLookupMock;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();

        permissionResolver = new OctopusPermissionResolver();
    }

    private void finishSetup() {
        beanManagerFake.endRegistration();
        permissionResolver.init();
    }

    @After
    public void teardown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void resolvePermission_simpleName() {
        finishSetup();
        Permission permission = permissionResolver.resolvePermission("Demo");
        assertThat(permission).isInstanceOf(WildcardPermission.class);
        WildcardPermission wildcardPermission = (WildcardPermission) permission;
        assertThat(wildcardPermission.toString()).isEqualTo("[demo]:[*]:[*]");
    }

    @Test
    public void resolvePermission_wildCardPermission() {
        finishSetup();
        Permission permission = permissionResolver.resolvePermission("oTheR:reAD:sOme");
        assertThat(permission).isInstanceOf(WildcardPermission.class);
        WildcardPermission wildcardPermission = (WildcardPermission) permission;
        assertThat(wildcardPermission.toString()).isEqualTo("[other]:[read]:[some]");
    }

    @Test
    public void resolvePermission_StringLookup() {
        beanManagerFake.registerBean(stringPermissionLookupMock, StringPermissionLookup.class);
        finishSetup();

        NamedDomainPermission namedDomainPermission = new NamedDomainPermission("somePermission", "JUnit", "test", "*");
        when(stringPermissionLookupMock.getPermission("somePermission")).thenReturn(namedDomainPermission);

        Permission permission = permissionResolver.resolvePermission("somePermission");
        assertThat(permission).isInstanceOf(NamedDomainPermission.class);
        NamedDomainPermission domainPermission = (NamedDomainPermission) permission;
        assertThat(domainPermission.getWildcardNotation()).isEqualTo("JUnit:test:*");
    }

    @Test
    public void resolvePermission_PermissionLookup() {
        beanManagerFake.registerBean(permissionLookupMock, PermissionLookup.class);
        finishSetup();

        NamedDomainPermission namedDomainPermission = new NamedDomainPermission("otherPermission", "other", "*", "hi");
        when(permissionLookupMock.getPermission("otherPermission")).thenReturn(namedDomainPermission);

        Permission permission = permissionResolver.resolvePermission("otherPermission");
        assertThat(permission).isInstanceOf(NamedDomainPermission.class);
        NamedDomainPermission domainPermission = (NamedDomainPermission) permission;
        assertThat(domainPermission.getWildcardNotation()).isEqualTo("other:*:hi");
    }


}