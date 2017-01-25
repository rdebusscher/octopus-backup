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
package be.c4j.ee.security.authentication;

import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;

/**
 *
 */
public class ExternalPasswordAuthenticationInfo extends SimpleAuthenticationInfo {

    private static Logger LOGGER = LoggerFactory.getLogger(ExternalPasswordAuthenticationInfo.class);

    public ExternalPasswordAuthenticationInfo(Object principal, String realmName) {
        this.principals = new SimplePrincipalCollection(principal, realmName);
    }

    public void addUserInfo(Serializable key, Serializable value) {
        Object primaryPrincipal = getPrincipals().getPrimaryPrincipal();
        if (primaryPrincipal instanceof UserPrincipal) {
            ((UserPrincipal) primaryPrincipal).addUserInfo(key, value);
        } else {
            LOGGER.info("Adding user info is only possible on an Octopus Principal. Type of principal is " + primaryPrincipal.getClass().getName());
        }
    }

    public void setName(String name) {
        Object primaryPrincipal = getPrincipals().getPrimaryPrincipal();
        if (primaryPrincipal instanceof UserPrincipal) {
            ((UserPrincipal) primaryPrincipal).setName(name);
        } else {
            LOGGER.info("Set name is only possible on an Octopus Principal. Type of principal is " + primaryPrincipal.getClass().getName());

        }
    }
}
