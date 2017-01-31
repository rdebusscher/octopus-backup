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
package be.c4j.ee.security.realm;

import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.NamedPermission;
import org.apache.shiro.authz.AuthorizationInfo;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class AuthorizationInfoBuilderTest {

    private AuthorizationInfoBuilder builder;

    @Before
    public void setup() {
        builder = new AuthorizationInfoBuilder();
    }

    @Test
    public void build() {
        AuthorizationInfo info = builder.build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).isEmpty();
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isNull();
    }

    @Test
    public void addPermission_simpleString() {
        // simple permission as String will be translated by PermissionResolver
        AuthorizationInfo info = builder.addPermission("JUnit").build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).hasSize(1);
        assertThat(info.getStringPermissions()).contains("JUnit");
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isNull();
    }

    @Test
    public void addPermission_wildCard() {
        AuthorizationInfo info = builder.addPermission("JUnit:*:*").build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).hasSize(1);
        assertThat(info.getStringPermissions()).contains("JUnit:*:*");
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isNull();
    }

    @Test
    public void addPermission_namedPermission() {
        AuthorizationInfo info = builder.addPermission(new SimplePermission("JUnit")).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).hasSize(1);
        assertThat(info.getStringPermissions()).contains("JUnit");
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isNull();
    }

    @Test
    public void addPermission_domainPermission() {
        AuthorizationInfo info = builder.addPermission(new NamedDomainPermission("theName", "JUnit", "*", "*")).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).isEmpty();
        assertThat(info.getObjectPermissions()).hasSize(1);
        assertThat(info.getRoles()).isNull();
    }

    @Test
    public void addPermission_multiple() {

        AuthorizationInfo info = builder.addPermission("JUnit").addPermission("another").build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).hasSize(2);
        assertThat(info.getStringPermissions()).contains("JUnit", "another");
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isNull();
    }

    @Test
    public void addPermission_noDuplicates() {

        AuthorizationInfo info = builder.addPermission("JUnit").addPermission("JUnit").build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).hasSize(1);
        assertThat(info.getStringPermissions()).contains("JUnit");
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isNull();
    }

    @Test
    public void addPermissions_stringPermission() {

        List<String> permissions = new ArrayList<String>();
        permissions.add("JUnit");
        permissions.add("anotherPermission");
        AuthorizationInfo info = builder.addStringPermissions(permissions).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).hasSize(2);
        assertThat(info.getStringPermissions()).contains("JUnit", "anotherPermission");
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isNull();
    }

    @Test
    public void addPermissions_stringPermissionNoDuplicates() {

        List<String> permissions = new ArrayList<String>();
        permissions.add("JUnit");
        permissions.add("anotherPermission");
        permissions.add("JUnit");
        AuthorizationInfo info = builder.addStringPermissions(permissions).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).hasSize(2);
        assertThat(info.getStringPermissions()).contains("JUnit", "anotherPermission");
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isNull();
    }

    @Test
    public void addPermissions_namedPermission() {

        List<NamedPermission> permissions = new ArrayList<NamedPermission>();
        permissions.add(new SimplePermission("JUnit"));
        permissions.add(new SimplePermission("anotherPermission"));
        AuthorizationInfo info = builder.addPermissions(permissions).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).hasSize(2);
        assertThat(info.getStringPermissions()).contains("JUnit", "anotherPermission");
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isNull();
    }

    @Test
    public void addPermissions_domainPermission() {
        List<NamedDomainPermission> permissions = new ArrayList<NamedDomainPermission>();
        permissions.add(new NamedDomainPermission("theName", "JUnit", "*", "*"));
        permissions.add(new NamedDomainPermission("other", "other", "*", "*"));
        AuthorizationInfo info = builder.addPermissions(permissions).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).isEmpty();
        assertThat(info.getObjectPermissions()).hasSize(2);
        assertThat(info.getRoles()).isNull();
    }

    @Test
    public void addPermissions_noDuplicates() {

        List<NamedPermission> permissions = new ArrayList<NamedPermission>();
        permissions.add(new SimplePermission("JUnit"));
        permissions.add(new SimplePermission("JUnit"));
        AuthorizationInfo info = builder.addPermissions(permissions).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).hasSize(1);
        assertThat(info.getStringPermissions()).contains("JUnit");
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isNull();
    }


    private static class SimplePermission implements NamedPermission {

        private String name;

        public SimplePermission(String name) {
            this.name = name;
        }

        @Override
        public String name() {
            return name;
        }
    }
}