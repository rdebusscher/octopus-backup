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
package be.c4j.demo.security;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.fake.LoginAuthenticationTokenProvider;
import com.github.scribejava.core.model.OAuth2AccessToken;
import org.apache.shiro.authc.AuthenticationToken;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class DemoLoginAuthenticationTokenProvider implements LoginAuthenticationTokenProvider {

    @Override
    public AuthenticationToken determineAuthenticationToken(String loginData) {

        OAuth2User user;

        if ("test".equals(loginData)) {
            user = testUser();
        } else {
            user = defaultUser();
        }

        return user;
    }

    private OAuth2User defaultUser() {
        OAuth2User result = new OAuth2User();
        result.setFirstName("_Rudy_");
        result.setLastName("_De Busscher_");

        // These are all required
        result.setFullName("_Rudy De Busscher_");
        result.setId("Fake");
        result.setDomain("c4j.be");
        result.setEmail("rudy.debusscher@c4j.be");
        result.setToken(new OAuth2AccessToken("Fake", ""));
        return result;
    }

    private OAuth2User testUser() {
        OAuth2User result = new OAuth2User();
        result.setFirstName("_test_");
        result.setLastName("_Account_");

        // These are all required
        result.setFullName("_test account_");
        result.setId("Fake");
        result.setDomain("acme.org");
        result.setEmail("test.account@acme.org");
        result.setToken(new OAuth2AccessToken("Fake", ""));
        return result;
    }
}
