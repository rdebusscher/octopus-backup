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
package be.c4j.ee.security.credentials.authentication.oauth2;

import be.c4j.ee.security.shiro.ValidatedAuthenticationToken;
import com.github.scribejava.core.model.Token;

import javax.security.auth.Subject;
import java.io.Serializable;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
//@JsonIgnoreProperties(value = {"token", "userInfo", "principal", "credentials"}, ignoreUnknown = true)
// This was placed here because of the Serialization of the OAuth2USer from UserController to SSOCallbackServlet (Old sso-client)
public class OAuth2User implements ValidatedAuthenticationToken, Principal {

    public static final String LOCAL_ID = "LOCAL_ID";

    public static final String OAUTH2_USER_INFO = "oAuth2UserInfo";

    private String id;

    private String localId;

    private String lastName;

    private String fullName;

    private String picture;

    private String gender;

    private String locale;

    private String email;

    private String link;

    private String firstName;

    private String domain;

    private boolean verifiedEmail;  // Needs to become properties

    private Map<String, String> userInfo = new HashMap<String, String>();

    private Map<String, String> info = new HashMap<String, String>();

    private Token token;

    private String applicationName;

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

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getLocale() {
        return locale;
    }

    public void setLocale(String locale) {
        this.locale = locale;
    }

    public String getLink() {
        return link;
    }

    public void setLink(String link) {
        this.link = link;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public boolean isVerifiedEmail() {
        return verifiedEmail;
    }

    public void setVerifiedEmail(boolean verifiedEmail) {
        this.verifiedEmail = verifiedEmail;
    }

    public void addUserInfo(String key, String value) {
        userInfo.put(key, value);
    }

    public boolean isLoggedOn() {
        return id != null;
    }

    public Token getToken() {
        return token;
    }

    public void setToken(Token token) {
        this.token = token;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    public Map<String, String> getInfo() {
        return info;
    }

    public void setInfo(Map<String, String> info) {
        this.info = info;
    }

    public Map<Serializable, Serializable> getUserInfo() {
        Map<Serializable, Serializable> result = new HashMap<Serializable, Serializable>();
        // TODO Make some constants out of these
        result.put("email", email);
        result.put("picture", picture);
        result.put("gender", gender);
        result.put("domain", domain);
        result.put("locale", locale);
        if (token != null) {
            result.put("token", token.getToken());
        }
        result.putAll(userInfo);

        return result;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("GoogleUser{");
        sb.append("id='").append(id).append('\'');
        sb.append(", lastName='").append(lastName).append('\'');
        sb.append(", fullName='").append(fullName).append('\'');
        sb.append(", picture='").append(picture).append('\'');
        sb.append(", gender='").append(gender).append('\'');
        sb.append(", email='").append(email).append('\'');
        sb.append(", link='").append(link).append('\'');
        sb.append(", firstName='").append(firstName).append('\'');
        sb.append(", domain='").append(domain).append('\'');
        sb.append(", verifiedEmail=").append(verifiedEmail);
        sb.append(", Octopus-app='").append(applicationName).append('\'');
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
        return new GooglePrincipal(id, email);
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    public static class GooglePrincipal {
        private String id;
        private String email;

        public GooglePrincipal(String id, String email) {
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
