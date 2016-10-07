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
package be.c4j.ee.security.sso;

import be.c4j.ee.security.shiro.ValidatedAuthenticationToken;
import org.json.JSONException;
import org.json.JSONObject;

import javax.security.auth.Subject;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public class OctopusSSOUser implements ValidatedAuthenticationToken, Principal {

    public static final String USER_INFO_KEY = OctopusSSOUser.class.getSimpleName();

    public static final String SSO_USER_INFO = "ssoUserInfo";

    private String id;
    private String localId;
    private String userName;
    private String token;

    private String lastName;
    private String firstName;
    private String fullName;

    private String email;

    private Map<String, String> userInfo = new HashMap<String, String>();

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

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
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

    public void addUserInfo(String key, String value) {
        userInfo.put(key, value);
    }

    public boolean isLoggedOn() {
        return id != null;
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
        return token;
    }

    public String toJSON() {
        JSONObject result = new JSONObject();
        try {
            result.put("id", id);
            result.put("localId", localId);
            result.put("userName", userName);

            result.put("lastName", lastName);
            result.put("firstName", firstName);
            result.put("fullName", fullName);
            result.put("email", email);
        } catch (JSONException e) {
            // FIXME
            e.printStackTrace();
        }

        return result.toString();
    }

    public static OctopusSSOUser fromJSON(String json) {
        OctopusSSOUser result = null;
        try {
            JSONObject jsonObject = new JSONObject(json);
            result = new OctopusSSOUser();
            result.setId(jsonObject.getString("id"));
            result.setLocalId(jsonObject.getString("localId"));
            result.setUserName(jsonObject.getString("userName"));

            result.setLastName(jsonObject.getString("lastName"));
            result.setFirstName(jsonObject.getString("firstName"));
            result.setFullName(jsonObject.getString("fullName"));
            result.setEmail(jsonObject.getString("email"));

        } catch (JSONException e) {
            // FIXME
            e.printStackTrace();
        }
        return result;
    }
}
