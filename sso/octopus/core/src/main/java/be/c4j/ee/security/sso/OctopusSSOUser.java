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

import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.shiro.ValidatedAuthenticationToken;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.security.auth.Subject;
import java.io.Serializable;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 */
public class OctopusSSOUser implements ValidatedAuthenticationToken, Principal {

    public static final String LOCAL_ID = "localId";
    private static final List<String> DEFAULT_PROPERTY_NAMES = Arrays.asList("id", LOCAL_ID, "userName", "lastName", "firstName", "fullName", "email");

    private String id;
    private String localId;
    private String userName;
    private String token;

    private String lastName;
    private String firstName;
    private String fullName;

    private String email;

    private Map<String, Serializable> userInfo = new HashMap<String, Serializable>();

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

    public void addUserInfo(Map<String, Serializable> info) {
        for (Map.Entry<String, Serializable> entry : info.entrySet()) {
            userInfo.put(entry.getKey(), entry.getValue());
        }
    }

    public boolean isLoggedOn() {
        return id != null;
    }

    public Map<String, Serializable> getUserInfo() {
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
        return token;
    }

    public <T extends Serializable> T getUserInfo(String key) {
        return (T) userInfo.get(key);
    }

    public String toJSON(Map<String, Serializable> info) {
        JSONObject result = new JSONObject();
        try {
            result.put("id", id);
            result.put("localId", localId);
            result.put("userName", userName);

            result.put("lastName", lastName);
            result.put("firstName", firstName);
            result.put("fullName", fullName);
            result.put("email", email);

            for (Map.Entry<String, Serializable> infoEntry : info.entrySet()) {
                result.put(infoEntry.getKey(), infoEntry.getValue());
            }

        } catch (JSONException e) {
            throw new OctopusUnexpectedException(e);
        }

        return result.toString();
    }

    public static OctopusSSOUser fromJSON(String json) {
        OctopusSSOUser result;
        try {
            JSONObject jsonObject = new JSONObject(json);
            result = new OctopusSSOUser();
            result.setId(jsonObject.getString("id"));
            result.setLocalId(jsonObject.getString("localId"));
            result.setUserName(jsonObject.optString("userName"));  // username is optional like for example with OAuth2

            result.setLastName(jsonObject.optString("lastName"));
            result.setFirstName(jsonObject.optString("firstName"));
            result.setFullName(jsonObject.optString("fullName"));
            result.setEmail(jsonObject.optString("email"));


            JSONArray names = jsonObject.names();
            String keyName;
            for (int i = 0; i < names.length(); i++) {
                keyName = names.get(i).toString();
                if (!DEFAULT_PROPERTY_NAMES.contains(keyName)) {
                    result.addUserInfo(keyName, jsonObject.getString(keyName));
                }
            }
        } catch (JSONException e) {
            throw new OctopusUnexpectedException(e);
        }
        return result;
    }
}
