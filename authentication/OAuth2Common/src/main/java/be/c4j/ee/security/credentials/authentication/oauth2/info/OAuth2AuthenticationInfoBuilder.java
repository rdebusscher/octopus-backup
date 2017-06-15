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
import be.c4j.ee.security.realm.AuthenticationInfoBuilder;
import org.apache.shiro.authc.AuthenticationInfo;

import java.util.HashMap;
import java.util.Map;

/**
 * Use this class witin be.c4j.ee.security.realm.SecurityDataProvider#getAuthenticationInfo(org.apache.shiro.authc.AuthenticationToken)
 */
public class OAuth2AuthenticationInfoBuilder {


    private OAuth2User oauth2User;

    private Map<String, Object> userInfo = new HashMap<String, Object>();

    public OAuth2AuthenticationInfoBuilder(OAuth2User oauth2User) {
        this.oauth2User = oauth2User;
    }

    public OAuth2AuthenticationInfoBuilder addUserInfo(String key, Object value) {
        userInfo.put(key, value);
        return this;
    }

    public OAuth2AuthenticationInfoBuilder addUserInfo(Map<String, Object> values) {
        userInfo.putAll(values);
        return this;
    }

    public AuthenticationInfo build() {
        AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();

        builder.principalId(oauth2User.getLocalId() == null ? oauth2User.getId() : oauth2User.getLocalId())
                .name(oauth2User.getName())
                .userName(oauth2User.getEmail());
        builder.addUserInfo(oauth2User.getUserInfo());
        builder.addUserInfo(userInfo);

        return builder.build();
    }

}
