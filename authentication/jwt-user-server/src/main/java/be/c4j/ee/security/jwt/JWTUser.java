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
package be.c4j.ee.security.jwt;

import be.c4j.ee.security.shiro.ValidatedAuthenticationToken;

import java.io.Serializable;
import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 */
public class JWTUser implements ValidatedAuthenticationToken, Principal {

    private String name;
    private String id;
    private String externalId;

    private String userName;

    private List<String> roles;
    private List<String> permissions;

    private Map<String, Serializable> userInfo;

    public JWTUser(String subject, String id) {
        name = subject;
        this.id = id;
        userInfo = new HashMap<String, Serializable>();
    }

    @Override
    public String getName() {
        return name;
    }

    public String getId() {
        return id;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getExternalId() {
        return externalId;
    }

    public void setExternalId(String externalId) {
        this.externalId = externalId;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public List<String> getPermissions() {
        return permissions;
    }

    public void setPermissions(List<String> permissions) {
        this.permissions = permissions;
    }

    public void addUserInfo(Map<String, Serializable> info) {
        userInfo.putAll(info);
    }

    public Map<String, Serializable> getUserInfo() {
        return userInfo;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public Object getCredentials() {
        return null;
    }
}
