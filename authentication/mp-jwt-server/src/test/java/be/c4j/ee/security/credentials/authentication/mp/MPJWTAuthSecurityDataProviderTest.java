/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.c4j.ee.security.credentials.authentication.mp;

import be.c4j.ee.security.OctopusConstants;
import be.c4j.ee.security.credentials.authentication.mp.token.MPJWTToken;
import be.c4j.ee.security.credentials.authentication.mp.token.MPToken;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.role.NamedApplicationRole;
import be.c4j.test.util.BeanManagerFake;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.junit.After;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class MPJWTAuthSecurityDataProviderTest {

    private BeanManagerFake beanManagerFake = new BeanManagerFake();

    @After
    public void cleanup() {
        beanManagerFake.deregistration();
    }

    @Test
    public void getAuthenticationInfo() {
        beanManagerFake.endRegistration();

        MPJWTAuthSecurityDataProvider dataProvider = new MPJWTAuthSecurityDataProvider();

        MPJWTToken mpjwtToken = new MPJWTToken();
        mpjwtToken.setJti("id");
        mpjwtToken.setPreferredUsername("userName");
        mpjwtToken.addAdditionalClaims("name", "fullName");
        AuthenticationToken mpToken = new MPToken(mpjwtToken);

        AuthenticationInfo info = dataProvider.getAuthenticationInfo(mpToken);
        assertThat(info).isNotNull();
        assertThat(info.getPrincipals()).isNotNull();
        assertThat(info.getPrincipals().getPrimaryPrincipal()).isNotNull();
        assertThat(info.getPrincipals().getPrimaryPrincipal()).isInstanceOf(UserPrincipal.class);

        UserPrincipal userPrincipal = (UserPrincipal) info.getPrincipals().getPrimaryPrincipal();
        assertThat(userPrincipal.getId()).isEqualTo("id");
        assertThat(userPrincipal.getUserName()).isEqualTo("userName");
        assertThat(userPrincipal.getName()).isEqualTo("fullName");

        assertThat(userPrincipal.getInfo()).hasSize(1);
        assertThat(userPrincipal.getUserInfo("name")).isEqualTo("fullName");
    }

    @Test
    public void getAuthorizationInfo() {

        MPJWTAuthSecurityDataProvider dataProvider = new MPJWTAuthSecurityDataProvider();

        MPJWTToken mpjwtToken = new MPJWTToken();
        mpjwtToken.setGroups(Arrays.asList("group1", "junit:test:*"));
        AuthenticationToken mpToken = new MPToken(mpjwtToken);

        UserPrincipal userPrincipal = new UserPrincipal("id", "userName", "fullName");
        userPrincipal.addUserInfo(OctopusConstants.TOKEN, mpToken);
        PrincipalCollection principals = new SimplePrincipalCollection(userPrincipal, "DEFAULT");

        beanManagerFake.endRegistration();

        AuthorizationInfo info = dataProvider.getAuthorizationInfo(principals);
        assertThat(info).isNotNull();

        assertThat(info.getStringPermissions()).isEmpty();
        assertThat(info.getRoles()).isNull();

        List<String> namedDomainPermissions = new ArrayList<String>();
        List<String> namedApplicationRoles = new ArrayList<String>();
        for (Permission permission : info.getObjectPermissions()) {
            if (permission instanceof NamedDomainPermission) {
                namedDomainPermissions.add(((NamedDomainPermission) permission).getWildcardNotation());
            }
            if (permission instanceof NamedApplicationRole) {
                namedApplicationRoles.add(((NamedApplicationRole) permission).getRoleName());
            }
        }

        assertThat(namedDomainPermissions).containsOnly("group1:*:*", "junit:test:*");
        assertThat(namedApplicationRoles).containsOnly("group1");
    }

}