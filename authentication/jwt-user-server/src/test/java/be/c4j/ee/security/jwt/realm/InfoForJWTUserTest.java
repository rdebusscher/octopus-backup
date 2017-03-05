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
package be.c4j.ee.security.jwt.realm;

import be.c4j.ee.security.jwt.JWTUser;
import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.junit.Before;
import org.junit.Test;
import sun.security.acl.PrincipalImpl;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class InfoForJWTUserTest {

    private InfoForJWTUser infoForJWTUser;

    @Before
    public void setup() {
        infoForJWTUser = new InfoForJWTUser();
    }

    @Test
    public void getAuthenticationInfo_WrongToken() {
        AuthenticationInfo info = infoForJWTUser.getAuthenticationInfo(new UsernamePasswordToken());
        assertThat(info).isNull();
    }

    @Test
    public void getAuthenticationInfo() {
        JWTUser jwtUser = new JWTUser("subject", "id");
        jwtUser.setUserName("username");
        Map<String, Serializable> userInfo = new HashMap<String, Serializable>();
        userInfo.put("key", "JUnit");
        jwtUser.addUserInfo(userInfo);

        AuthenticationInfo info = infoForJWTUser.getAuthenticationInfo(jwtUser);
        assertThat(info).isNotNull();

        Object principal = info.getPrincipals().getPrimaryPrincipal();
        assertThat(principal).isInstanceOf(UserPrincipal.class);

        UserPrincipal userPrincipal = (UserPrincipal) principal;
        assertThat(userPrincipal.getId()).isEqualTo("id");
        assertThat(userPrincipal.getName()).isEqualTo("subject");
        assertThat(userPrincipal.getUserName()).isEqualTo("username");

        assertThat(userPrincipal.getInfo()).hasSize(2);
        assertThat(userPrincipal.getInfo()).containsEntry("key", "JUnit");
        assertThat(userPrincipal.getInfo()).containsEntry("externalId", null);
    }

    @Test
    public void getAuthorizationInfo_WrongPrincipal() {

        AuthorizationInfo info = infoForJWTUser.getAuthorizationInfo(new PrincipalImpl("X"));
        assertThat(info).isNull();
    }

    @Test
    public void getAuthorizationInfo_NoToken() {

        UserPrincipal userPrincipal = new UserPrincipal();
        AuthorizationInfo info = infoForJWTUser.getAuthorizationInfo(userPrincipal);
        assertThat(info).isNull();
    }

    @Test
    public void getAuthorizationInfo() {

        JWTUser jwtUser = new JWTUser("subject", "id");
        List<String> permissions = new ArrayList<String>();

        permissions.add("permission");
        jwtUser.setPermissions(permissions);

        List<String> roles = new ArrayList<String>();
        jwtUser.setRoles(roles);

        UserPrincipal userPrincipal = new UserPrincipal();
        userPrincipal.addUserInfo("token", jwtUser);
        AuthorizationInfo info = infoForJWTUser.getAuthorizationInfo(userPrincipal);
        assertThat(info).isNotNull();

        assertThat(info.getStringPermissions()).containsExactly("permission");
        assertThat(info.getRoles()).isNull();
    }

}