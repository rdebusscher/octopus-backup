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
package be.c4j.ee.security.credentials.authentication.keycloak;

import be.c4j.ee.security.OctopusConstants;
import be.c4j.ee.security.token.AbstractOctopusAuthenticationToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;

import javax.security.auth.Subject;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public class KeycloakUser extends AbstractOctopusAuthenticationToken {

    private String id;

    private String localId;

    private String lastName;

    private String fullName;

    private String picture;

    private String gender;

    private String locale;

    private String email;

    private String firstName;

    private AccessTokenResponse accessToken;

    private String clientSession;

    private KeycloakUser() {
    }

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

    public String getPicture() {
        return picture;
    }

    public void setPicture(String picture) {
        this.picture = picture;
    }

    public String getGender() {
        return gender;
    }

    public void setGender(String gender) {
        this.gender = gender;
    }

    public String getLocale() {
        return locale;
    }

    public void setLocale(String locale) {
        this.locale = locale;
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

    public AccessTokenResponse getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(AccessTokenResponse accessToken) {
        this.accessToken = accessToken;
    }

    public String getClientSession() {
        return clientSession;
    }

    public void setClientSession(String clientSession) {
        this.clientSession = clientSession;
    }

    public Map<String, Object> getUserInfo() {
        // TODO Rename?
        Map<String, Object> result = new HashMap<String, Object>();

        result.put(OctopusConstants.EMAIL, email);
        result.put(OctopusConstants.PICTURE, picture);
        result.put(OctopusConstants.GENDER, gender);
        result.put(OctopusConstants.LOCALE, locale);
        if (accessToken != null) {
            result.put(OctopusConstants.TOKEN, accessToken.getToken());
        }

        result.putAll(userInfo);

        return result;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("KeycloakUser{");
        sb.append("id='").append(id).append('\'');
        sb.append(", lastName='").append(lastName).append('\'');
        sb.append(", fullName='").append(fullName).append('\'');
        sb.append(", picture='").append(picture).append('\'');
        sb.append(", gender='").append(gender).append('\'');
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
        return new KeycloakPrincipal(id, email);
    }

    @Override
    public Object getCredentials() {
        return accessToken;
    }

    public static KeycloakUser fromIdToken(IDToken token) {
        KeycloakUser result = new KeycloakUser();
        result.setId(token.getId());
        result.setFullName(token.getName());
        result.setFirstName(token.getGivenName());
        result.setLastName(token.getFamilyName());

        result.setEmail(token.getEmail());

        result.setGender(token.getGender());
        result.setLocale(token.getLocale());
        result.setPicture(token.getPicture());

        return result;
    }

    public static class KeycloakPrincipal {
        private String id;
        private String email;

        public KeycloakPrincipal(String id, String email) {
            this.id = id;
            this.email = email;
        }

        public String getId() {
            return id;
        }

        public String getEmail() {
            return email;
        }
    }

}
