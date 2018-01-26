/*
 * Copyright 2014-2018 Rudy De Busscher
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
package be.c4j.ee.security.realm;

import be.c4j.ee.security.PublicAPI;
import be.c4j.ee.security.authentication.ExternalPasswordAuthenticationInfo;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.util.SimpleByteSource;
import org.apache.shiro.util.StringUtils;

import javax.enterprise.inject.Typed;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import static be.c4j.ee.security.OctopusConstants.AUTHORIZATION_INFO;

/**
 *
 */
@Typed
@PublicAPI
public class AuthenticationInfoBuilder {

    public static final String DEFAULT_REALM = "OctopusApp";

    private Serializable principalId;
    private String name;
    private String userName;
    private Object password;
    private String realmName = DEFAULT_REALM;
    private ByteSource salt;
    private Map<String, Object> userInfo = new HashMap<String, Object>();
    private boolean externalPasswordCheck = false;
    private Boolean needs2StepAuthentication;

    public AuthenticationInfoBuilder principalId(Serializable principalId) {
        this.principalId = principalId;
        return this;
    }

    public AuthenticationInfoBuilder name(String name) {
        this.name = name;
        return this;
    }

    public AuthenticationInfoBuilder userName(String userName) {
        this.userName = userName;
        return this;
    }

    public AuthenticationInfoBuilder password(Object password) {
        this.password = password;
        return this;

    }

    public AuthenticationInfoBuilder realmName(String realmName) {
        if (!StringUtils.hasText(realmName)) {
            throw new OctopusConfigurationException("Realm name can't be empty");
        }
        this.realmName = realmName;
        return this;
    }

    public AuthenticationInfoBuilder salt(ByteSource salt) {
        this.salt = salt;
        return this;
    }

    public AuthenticationInfoBuilder salt(byte[] salt) {
        this.salt(new SimpleByteSource(salt));
        return this;
    }

    public AuthenticationInfoBuilder externalPasswordCheck() {
        this.externalPasswordCheck = true;
        return this;
    }

    public AuthenticationInfoBuilder needs2StepAuthentication(boolean twoStepAuthentication) {
        this.needs2StepAuthentication = twoStepAuthentication;
        return this;
    }

    public AuthenticationInfoBuilder addUserInfo(String key, Serializable value) {
        userInfo.put(key, value);
        return this;
    }

    public AuthenticationInfoBuilder addUserInfo(Map<String, Object> values) {
        userInfo.putAll(values);
        return this;
    }

    public AuthenticationInfoBuilder addAuthorizationInfo(AuthorizationInfo authorizationInfo) {
        addUserInfo(AUTHORIZATION_INFO, authorizationInfo);
        return this;
    }

    public AuthenticationInfo build() {
        if (principalId == null) {
            throw new IllegalArgumentException("principalId is required for an authenticated user");
        }
        UserPrincipal principal = new UserPrincipal(principalId, userName, name);
        principal.setNeedsTwoStepAuthentication(needs2StepAuthentication);
        principal.addUserInfo(userInfo);
        AuthenticationInfo result;
        if (salt == null) {
            if (externalPasswordCheck) {
                result = new ExternalPasswordAuthenticationInfo(principal, realmName);
            } else {
                result = new SimpleAuthenticationInfo(principal, password, realmName);
            }
        } else {
            // Using a salt doesn't has anything to do with the salt length parameter (OctopusConfig#getSaltLength)
            // That parameter is only used when creating new salts (through SaltHashingUtil)
            result = new SimpleAuthenticationInfo(principal, password, salt, realmName);
        }
        return result;
    }

}
