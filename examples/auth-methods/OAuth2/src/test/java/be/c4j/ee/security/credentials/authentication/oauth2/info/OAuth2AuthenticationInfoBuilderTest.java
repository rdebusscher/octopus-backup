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
package be.c4j.ee.security.credentials.authentication.oauth2.info;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.authc.AuthenticationInfo;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class OAuth2AuthenticationInfoBuilderTest {

    private static final String USER_ID = "userId";
    private static final String LOCAL_ID = "localId";
    private static final String EMAIL = "email";
    private static final String FULL_NAME = "fullName";
    private static final String KEY = "key";
    private static final String VALUE = "value";

    private OAuth2AuthenticationInfoBuilder builder;

    @Test
    public void build() {
        OAuth2User user = new OAuth2User();
        user.setId(USER_ID);
        user.setEmail(EMAIL);
        user.setFullName(FULL_NAME);
        builder = new OAuth2AuthenticationInfoBuilder(user);

        builder.addUserInfo(KEY, VALUE);

        AuthenticationInfo info = builder.build();

        UserPrincipal userPrincipal = (UserPrincipal) info.getPrincipals().getPrimaryPrincipal();
        assertThat(userPrincipal.getId()).isEqualTo(USER_ID);
        assertThat(userPrincipal.getName()).isEqualTo(FULL_NAME);
        assertThat(userPrincipal.getEmail()).isEqualTo(EMAIL);

        assertThat(userPrincipal.getInfo()).containsKey(KEY);
        assertThat(userPrincipal.getUserInfo(KEY)).isEqualTo(VALUE);
    }

    @Test
    public void build_localId() {
        OAuth2User user = new OAuth2User();
        user.setId(USER_ID);
        user.setLocalId(LOCAL_ID);
        user.setEmail(EMAIL);
        user.setFullName(FULL_NAME);
        builder = new OAuth2AuthenticationInfoBuilder(user);

        AuthenticationInfo info = builder.build();

        UserPrincipal userPrincipal = (UserPrincipal) info.getPrincipals().getPrimaryPrincipal();
        assertThat(userPrincipal.getId()).isEqualTo(LOCAL_ID);
        assertThat(userPrincipal.getName()).isEqualTo(FULL_NAME);
        assertThat(userPrincipal.getEmail()).isEqualTo(EMAIL);

    }

}