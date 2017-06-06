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
package be.c4j.ee.security.sso.client.access;

import be.c4j.ee.security.access.AfterSuccessfulLoginHandler;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import be.c4j.ee.security.systemaccount.SystemAccountAuthenticationToken;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
public class SSOAfterSuccessfulLoginHandler implements AfterSuccessfulLoginHandler {

    @Inject
    private OctopusSSOClientConfiguration ssoClientConfiguration;

    @Override
    public void onSuccessfulLogin(AuthenticationToken token, AuthenticationInfo info, Subject subject) {
        if (token instanceof SystemAccountAuthenticationToken) {
            // System accounts don't need to pass the check for the AccessPermission.
            return;
        }
        String accessPermission = ssoClientConfiguration.getAccessPermission();
        if (accessPermission != null && !accessPermission.isEmpty()) {
            subject.checkPermission(accessPermission);
        }
    }
}
