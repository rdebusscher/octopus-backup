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
import be.c4j.ee.security.sso.rest.PrincipalUserInfoJSONProvider;
import be.c4j.ee.security.sso.rest.reflect.Property;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONStyle;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

import javax.security.auth.Subject;
import java.io.Serializable;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static net.minidev.json.JSONStyle.FLAG_IGNORE_NULL;

/**
 *
 */
public class OctopusSSOUser implements ValidatedAuthenticationToken, Principal {

    public static final String LOCAL_ID = "localId";
    private static final List<String> DEFAULT_PROPERTY_NAMES = Arrays.asList("id", LOCAL_ID, "userName", "lastName", "firstName", "fullName", "email");

    private String id;
    private String localId;
    private String userName;
    private BearerAccessToken bearerAccessToken;
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
        return bearerAccessToken;
    }

    public <T> T getUserInfo(String key) {
        return (T) userInfo.get(key);
    }

    public String toJSON(Map<String, Object> info, PrincipalUserInfoJSONProvider jsonProvider) {
        JSONObject result = new JSONObject();
        result.put("id", id);
        result.put("localId", localId);
        result.put("userName", userName);

        result.put("lastName", lastName);
        result.put("firstName", firstName);
        result.put("fullName", fullName);
        result.put("email", email);

        for (Map.Entry<String, Object> infoEntry : info.entrySet()) {

            Object value = infoEntry.getValue();
            if (Property.isBasicPropertyType(value)) {
                result.put(infoEntry.getKey(), value);
            } else {
                result.put(infoEntry.getKey(), value.getClass().getName() + "@" + jsonProvider.writeValue(value));
            }
        }

        return result.toJSONString(new JSONStyle(FLAG_IGNORE_NULL));
    }

    public static OctopusSSOUser fromJSON(String json, PrincipalUserInfoJSONProvider jsonProvider) {
        OctopusSSOUser result;
        try {

            JSONParser parser = new JSONParser(JSONParser.MODE_PERMISSIVE);

            JSONObject jsonObject = (JSONObject) parser.parse(json);

            result = new OctopusSSOUser();
            result.setId(getString(jsonObject, "id"));
            result.setLocalId(getString(jsonObject, "localId"));
            result.setUserName(optString(jsonObject, "userName"));  // username is optional like for example with OAuth2

            result.setLastName(optString(jsonObject, "lastName"));
            result.setFirstName(optString(jsonObject, "firstName"));
            result.setFullName(optString(jsonObject, "fullName"));
            result.setEmail(optString(jsonObject, "email"));


            Object value;
            for (String keyName : jsonObject.keySet()) {

                if (!DEFAULT_PROPERTY_NAMES.contains(keyName)) {
                    String keyValue = getString(jsonObject, keyName);
                    if (keyValue.contains("@")) {

                        Class<?> aClass = tryToDefineClass(keyValue);
                        if (aClass != null) {
                            int markerPos = keyValue.indexOf("@");
                            value = jsonProvider.readValue(keyValue.substring(markerPos + 1), aClass);
                        } else {
                            value = keyValue; // We don't have the class, we keep the string representation for convenience.
                        }

                    } else {
                        value = keyValue;
                    }
                    // We always know that it is serializable because we started from a map which contains only serializables.
                    result.addUserInfo(keyName, (Serializable) value);
                }
            }


        } catch (ParseException e) {
            throw new OctopusUnexpectedException(e);
        }
        return result;
    }

    private static Class<?> tryToDefineClass(String keyValue) {
        Class<?> result = null;
        String[] parts = keyValue.split("@", 2);
        try {
            result = Class.forName(parts[0]);
        } catch (ClassNotFoundException e) {
            // Nothing to do here, we don't have that class on the classpath
        }

        return result;
    }


    private static String getString(JSONObject jsonObject, String key) {
        return jsonObject.get(key).toString();
    }

    private static String optString(JSONObject jsonObject, String key) {
        if (jsonObject.containsKey(key)) {
            return getString(jsonObject, key);
        } else {
            return null;
        }
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
