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
package be.c4j.ee.security.twostep;

import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;

import static be.c4j.ee.security.realm.AuthenticationInfoBuilder.DEFAULT_REALM;

/**
 *
 */
public class TwoStepAuthenticationInfo implements AuthenticationInfo {

    private TwoStepCredentialsMatcher matcher;
    private UserPrincipal userPrincipal;


    public TwoStepAuthenticationInfo(TwoStepCredentialsMatcher matcher, UserPrincipal userPrincipal) {
        this.matcher = matcher;
        this.userPrincipal = userPrincipal;
    }

    public TwoStepCredentialsMatcher getMatcher() {
        return matcher;
    }

    @Override
    public PrincipalCollection getPrincipals() {
        return new SimplePrincipalCollection(userPrincipal, DEFAULT_REALM);
    }

    @Override
    public Object getCredentials() {
        return null;
    }
}
