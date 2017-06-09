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
package be.c4j.ee.security.authentication.credentials.authentication.cas;

import be.c4j.ee.security.shiro.ValidatedAuthenticationToken;

import java.security.Principal;
import java.util.Map;

/**
 * TODO Align package structure with Oauth2User, OctopusSSOUser, ...
 * for now kept at the same location for backwards compatibility
 * With 0.9.8 (when integrating Shiro) we will have more backwards breaking changes)
 */
public class CasUser implements ValidatedAuthenticationToken, Principal {

    public static final String CAS_USER_INFO = "CASUserInfo";

    private String ticket;
    private String userName;
    private String email;
    private Map<String, Object> userInfo;

    public CasUser(String ticket) {
        this.ticket = ticket;
    }

    public String getTicket() {
        return ticket;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getUserName() {
        return userName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Map<String, Object> getUserInfo() {
        return userInfo;
    }

    public void setUserInfo(Map<String, Object> userInfo) {
        this.userInfo = userInfo;
    }

    @Override
    public Object getPrincipal() {
    /* FIXME email ? */
        return new CasPrincipal(userName, null);
    }

    @Override
    public Object getCredentials() {
        return ticket;
    }

    @Override
    public String getName() {
        return userName;
    }

    public static class CasPrincipal {
        private String id;
        private String email;

        public CasPrincipal(String id, String email) {
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
