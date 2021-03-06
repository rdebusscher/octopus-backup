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

import be.c4j.ee.security.OctopusConstants;
import be.c4j.ee.security.PublicAPI;
import be.c4j.ee.security.shiro.ValidatedAuthenticationToken;
import be.c4j.ee.security.token.AbstractOctopusAuthenticationToken;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.Token;

import java.util.HashMap;
import java.util.Map;

/**
 * TODO, Should be a *Token, but need to introduce this in a backwards compatible way (at least for a few versions)
 */
@PublicAPI
public class OAuth2User extends AbstractOctopusAuthenticationToken implements ValidatedAuthenticationToken {

    public static final String OAUTH2_USER_INFO = "oAuth2UserInfo";

    private String id;

    private String localId;

    private String lastName;

    private String picture;

    private String gender;

    private String locale;

    private String email;

    private String link;

    private String firstName;

    private String domain;

    private boolean verifiedEmail;  // Needs to become properties

    private Map<String, String> info = new HashMap<String, String>();

    private OAuth2AccessToken token;

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

    public boolean isLoggedOn() {
        return id != null;
    }

    public Token getToken() {
        return token;
    }

    public void setToken(OAuth2AccessToken token) {
        this.token = token;
    }

    public Map<String, String> getInfo() {
        return info;
    }

    public void setInfo(Map<String, String> info) {
        this.info = info;
    }

    public Map<String, Object> getUserInfo() {
        Map<String, Object> result = new HashMap<String, Object>();

        result.put(OctopusConstants.EMAIL, email);
        result.put(OctopusConstants.FIRST_NAME, firstName);
        result.put(OctopusConstants.LAST_NAME, lastName);
        result.put(OctopusConstants.PICTURE, picture);
        result.put(OctopusConstants.GENDER, gender);
        result.put(OctopusConstants.DOMAIN, domain);
        result.put(OctopusConstants.LOCALE, locale);
        if (token != null) {
            result.put(OctopusConstants.UPSTREAM_TOKEN, token.getAccessToken());
            result.put(OctopusConstants.OAUTH2_TOKEN, token);
        }
        result.putAll(userInfo);

        return result;
    }

    @Override
    public String toString() {
        return "OAuth2User{" + "id='" + id + '\'' +
                ", lastName='" + lastName + '\'' +
                ", fullName='" + fullName + '\'' +
                ", picture='" + picture + '\'' +
                ", gender='" + gender + '\'' +
                ", email='" + email + '\'' +
                ", link='" + link + '\'' +
                ", firstName='" + firstName + '\'' +
                ", domain='" + domain + '\'' +
                ", verifiedEmail=" + verifiedEmail +
                '}';
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
