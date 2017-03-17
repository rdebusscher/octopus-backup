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
package be.c4j.ee.security.sso;

import be.c4j.ee.security.shiro.ValidatedAuthenticationToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;

import javax.security.auth.Subject;
import java.io.Serializable;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public class OctopusSSOUser implements ValidatedAuthenticationToken, Principal {

    public static final String LOCAL_ID = "localId";

    private String id;
    private String localId;
    private String userName;
    private BearerAccessToken bearerAccessToken;  // Client side only. For server side tokens are kep at OIDCStoreData
    private String cookieToken;

    private String lastName;
    private String firstName;
    private String fullName;

    private String email;

    private Map<String, Object> userInfo = new HashMap<String, Object>();

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getLocalId() {
        return localId;
    }

    public void setLocalId(String localId) {
        this.localId = localId;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public BearerAccessToken getBearerAccessToken() {
        return bearerAccessToken;
    }

    public void setBearerAccessToken(BearerAccessToken bearerAccessToken) {
        this.bearerAccessToken = bearerAccessToken;
    }

    public String getAccessToken() {
        return bearerAccessToken.getValue();
    }

    public String getCookieToken() {
        return cookieToken;
    }

    public void setCookieToken(String cookieToken) {
        this.cookieToken = cookieToken;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public void addUserInfo(String key, Serializable value) {
        userInfo.put(key, value);
    }

    public void addUserInfo(Map<String, Object> info) {
        userInfo.putAll(info);
    }

    public boolean isLoggedOn() {
        return id != null;
    }

    public Map<String, Object> getUserInfo() {
        return userInfo;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("OctopusSSOUser{");
        sb.append("id='").append(id).append('\'');
        sb.append(", localId='").append(localId).append('\'');
        sb.append(", lastName='").append(lastName).append('\'');
        sb.append(", fullName='").append(fullName).append('\'');
        sb.append(", email='").append(email).append('\'');
        sb.append(", firstName='").append(firstName).append('\'');
        sb.append('}');
        return sb.toString();
    }

    @Override
    public String getName() {
        return fullName;
    }

    public boolean implies(Subject subject) {
        if (subject == null) {
            return false;
        }
        return subject.getPrincipals().contains(this);
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public Object getCredentials() {
        return cookieToken;
    }

    public <T> T getUserInfo(String key) {
        return (T) userInfo.get(key);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof OctopusSSOUser)) {
            return false;
        }

        OctopusSSOUser ssoUser = (OctopusSSOUser) o;

        // Important, we need to use the getters as o can be a proxy and sso.userName returns null!!
        if (userName != null ? !userName.equals(ssoUser.getUserName()) : ssoUser.getUserName() != null) {
            return false;
        }
        return id != null ? id.equals(ssoUser.getId()) : ssoUser.getId() == null;
    }

    @Override
    public int hashCode() {
        int result = id != null ? id.hashCode() : 0;
        result = 31 * result + (userName != null ? userName.hashCode() : 0);
        return result;
    }
}
