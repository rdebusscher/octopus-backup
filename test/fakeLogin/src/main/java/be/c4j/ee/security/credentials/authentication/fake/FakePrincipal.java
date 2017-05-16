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
package be.c4j.ee.security.credentials.authentication.fake;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;

import java.io.Serializable;
import java.security.Principal;

/**
 *
 */

public class FakePrincipal implements Principal, Serializable {


    private final AuthenticationInfo authenticationInfo;
    private final AuthorizationInfo authorizationInfo;

    public FakePrincipal(AuthenticationInfo authenticationInfo, AuthorizationInfo authorizationInfo) {

        this.authenticationInfo = authenticationInfo;
        this.authorizationInfo = authorizationInfo;
    }

    @Override
    public String getName() {
        return null;
    }

    public AuthenticationInfo getAuthenticationInfo() {
        return authenticationInfo;
    }

    public AuthorizationInfo getAuthorizationInfo() {
        return authorizationInfo;
    }
}
