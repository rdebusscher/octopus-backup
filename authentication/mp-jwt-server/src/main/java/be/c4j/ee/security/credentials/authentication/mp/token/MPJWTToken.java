/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.c4j.ee.security.credentials.authentication.mp.token;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represent the MP Auth token (can be used in a
 */
public class MPJWTToken implements Serializable {

    private String iss; // issuer
    private List<String> aud; // audience
    private String jti; // Unique identifier
    private Long exp; // expiration time
    private Long iat; // issued at
    private String sub; // subject
    private String upn; // value for name in Principal
    private String preferredUsername;  // value for name in Principal
    private List<String> groups = new ArrayList<String>();
        /*
    "iss": "https://server.example.com",
            "aud": "s6BhdRkqt3",
            "jti": "a-123",
            "exp": 1311281970,
            "iat": 1311280970,
            "sub": "24400320",
            "upn": "jdoe@server.example.com",
            "groups": ["red-group", "green-group", "admin-group", "admin"],
    */

    private List<String> roles;
    private Map<String, Object> additionalClaims;

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public List<String> getAud() {
        return aud;
    }

    public void setAud(List<String> aud) {
        this.aud = aud;
    }

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }

    public Long getExp() {
        return exp;
    }

    public void setExp(Long exp) {
        this.exp = exp;
    }

    public Long getIat() {
        return iat;
    }

    public void setIat(Long iat) {
        this.iat = iat;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getUpn() {
        return upn;
    }

    public void setUpn(String upn) {
        this.upn = upn;
    }

    public String getPreferredUsername() {
        return preferredUsername;
    }

    public void setPreferredUsername(String preferredUsername) {
        this.preferredUsername = preferredUsername;
    }

    public List<String> getGroups() {
        return groups;
    }

    public void setGroups(List<String> groups) {
        this.groups = groups;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public Map<String, Object> getAdditionalClaims() {
        return additionalClaims;
    }

    public String getAdditionalClaim(String key) {
        Object value = additionalClaims.get(key);
        return value == null ? null : value.toString();
    }

    public void setAdditionalClaims(Map<String, Object> additionalClaims) {
        this.additionalClaims = additionalClaims;
    }

    public void addAdditionalClaims(String key, String value) {
        if (additionalClaims == null) {
            additionalClaims = new HashMap<String, Object>();
        }
        additionalClaims.put(key, value);
    }

}
