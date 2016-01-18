/*
 * Copyright 2014-2016 Rudy De Busscher (www.c4j.be)
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
 *
 */
package be.c4j.ee.security.token;

import be.c4j.ee.security.authentication.ExternalPasswordAuthenticationInfo;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 *
 */
public class MultipleCredentialsMatcher implements CredentialsMatcher {

    private List<CredentialsMatcher> octopusDefinedMatchers;

    private List<CredentialsMatcher> applicationDefinedMatchers;

    public MultipleCredentialsMatcher() {
        octopusDefinedMatchers = new ArrayList<CredentialsMatcher>();
        octopusDefinedMatchers.add(new SimpleCredentialsMatcher());
        octopusDefinedMatchers.add(new SystemAccountCredentialMatcher());

        applicationDefinedMatchers = new ArrayList<CredentialsMatcher>();
    }

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        boolean result = false;
        Iterator<CredentialsMatcher> iterator = applicationDefinedMatchers.iterator();
        while (!result && iterator.hasNext()) {
            CredentialsMatcher matcher = iterator.next();
            result = matcher.doCredentialsMatch(token, info);
        }

        if (!(info instanceof ExternalPasswordAuthenticationInfo)) {
            iterator = octopusDefinedMatchers.iterator();
            while (!result && iterator.hasNext()) {
                CredentialsMatcher matcher = iterator.next();
                result = matcher.doCredentialsMatch(token, info);
            }
        }

        return result;
    }

    public void setMatcher(CredentialsMatcher credentialsMatcher) {
        if (!applicationDefinedMatchers.contains(credentialsMatcher)) {
            applicationDefinedMatchers.add(credentialsMatcher);
        }
    }
}
