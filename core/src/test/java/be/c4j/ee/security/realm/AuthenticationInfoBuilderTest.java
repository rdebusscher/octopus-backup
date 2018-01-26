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

import be.c4j.ee.security.authentication.ExternalPasswordAuthenticationInfo;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.SaltedAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.junit.Before;
import org.junit.Test;

import static be.c4j.ee.security.OctopusConstants.AUTHORIZATION_INFO;
import static org.assertj.core.api.Assertions.assertThat;

public class AuthenticationInfoBuilderTest {

    private AuthenticationInfoBuilder builder;

    @Before
    public void setup() {
        builder = new AuthenticationInfoBuilder();
    }

    @Test(expected = OctopusConfigurationException.class)
    public void realmName_incorrect1() {
        builder.realmName(null);
    }

    @Test(expected = OctopusConfigurationException.class)
    public void realmName_incorrect2() {
        builder.realmName("");
    }

    @Test(expected = OctopusConfigurationException.class)
    public void realmName_incorrect3() {
        builder.realmName("  ");
    }

    @Test
    public void build_standard() {
        builder.principalId("JUnit").userName("user").name("Test user")
                .password("pw")
                .addUserInfo("Key", "Value");

        AuthenticationInfo info = builder.build();

        assertThat(info).isNotInstanceOf(ExternalPasswordAuthenticationInfo.class);

        assertThat(info.getPrincipals()).hasSize(1);
        assertThat(info.getPrincipals().getPrimaryPrincipal()).isInstanceOf(UserPrincipal.class);

        UserPrincipal userPrincipal = (UserPrincipal) info.getPrincipals().getPrimaryPrincipal();
        assertThat(userPrincipal.getId()).isEqualTo("JUnit");
        assertThat(userPrincipal.getUserName()).isEqualTo("user");
        assertThat(userPrincipal.getName()).isEqualTo("Test user");
        assertThat(userPrincipal.getInfo()).hasSize(1);
        assertThat(userPrincipal.getInfo()).containsEntry("Key", "Value");

        assertThat(info.getCredentials()).isEqualTo("pw");

        assertThat(info).isInstanceOf(SaltedAuthenticationInfo.class);
        assertThat(((SaltedAuthenticationInfo) info).getCredentialsSalt()).isNull();

    }

    @Test
    public void build_salted() {
        builder.principalId("JUnit").userName("user").name("Test user")
                .password("pw").salt("salt".getBytes())
                .addUserInfo("Key", "Value");

        AuthenticationInfo info = builder.build();

        assertThat(info).isNotInstanceOf(ExternalPasswordAuthenticationInfo.class);
        assertThat(info.getPrincipals()).hasSize(1);
        assertThat(info.getPrincipals().getPrimaryPrincipal()).isInstanceOf(UserPrincipal.class);

        UserPrincipal userPrincipal = (UserPrincipal) info.getPrincipals().getPrimaryPrincipal();
        assertThat(userPrincipal.getId()).isEqualTo("JUnit");
        assertThat(userPrincipal.getUserName()).isEqualTo("user");
        assertThat(userPrincipal.getName()).isEqualTo("Test user");
        assertThat(userPrincipal.getInfo()).hasSize(1);
        assertThat(userPrincipal.getInfo()).containsEntry("Key", "Value");

        assertThat(info.getCredentials()).isEqualTo("pw");

        assertThat(info).isInstanceOf(SaltedAuthenticationInfo.class);
        assertThat(((SaltedAuthenticationInfo) info).getCredentialsSalt()).isNotNull();

    }

    @Test
    public void build_external() {
        builder.principalId("JUnit").userName("user").name("Test user")
                .externalPasswordCheck()
                .addUserInfo("Key", "Value");

        AuthenticationInfo info = builder.build();

        assertThat(info).isInstanceOf(ExternalPasswordAuthenticationInfo.class);
        assertThat(info.getPrincipals()).hasSize(1);
        assertThat(info.getPrincipals().getPrimaryPrincipal()).isInstanceOf(UserPrincipal.class);

        UserPrincipal userPrincipal = (UserPrincipal) info.getPrincipals().getPrimaryPrincipal();
        assertThat(userPrincipal.getId()).isEqualTo("JUnit");
        assertThat(userPrincipal.getUserName()).isEqualTo("user");
        assertThat(userPrincipal.getName()).isEqualTo("Test user");
        assertThat(userPrincipal.getInfo()).hasSize(1);
        assertThat(userPrincipal.getInfo()).containsEntry("Key", "Value");

    }

    @Test
    public void build_addAuthorizationInfo() {

        AuthorizationInfo authzInfo = new SimpleAuthorizationInfo();
        builder.principalId("JUnit")
                .addAuthorizationInfo(authzInfo);

        AuthenticationInfo info = builder.build();

        UserPrincipal userPrincipal = (UserPrincipal) info.getPrincipals().getPrimaryPrincipal();
        assertThat(userPrincipal.getInfo()).hasSize(1);
        assertThat(userPrincipal.getInfo()).containsKey(AUTHORIZATION_INFO);

    }
}