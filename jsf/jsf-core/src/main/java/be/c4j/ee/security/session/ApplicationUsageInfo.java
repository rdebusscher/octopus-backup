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
package be.c4j.ee.security.session;

import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.authc.AuthenticationToken;

import javax.servlet.http.HttpSession;

/**
 *
 */

public class ApplicationUsageInfo {


    private HttpSession httpSession;
    private UserPrincipal userPrincipal;
    private AuthenticationToken authenticationToken;
    private String userAgent;
    private String remoteHost;

    public ApplicationUsageInfo(HttpSession httpSession, String remoteHost, String userAgent) {
        this.httpSession = httpSession;
        this.remoteHost = remoteHost;
        this.userAgent = userAgent;
    }

    public HttpSession getHttpSession() {
        return httpSession;
    }

    public String getSessionId() {
        return httpSession.getId();
    }

    public String getUserAgent() {
        return userAgent;
    }

    public String getRemoteHost() {
        return remoteHost;
    }

    public UserPrincipal getUserPrincipal() {
        return userPrincipal;
    }

    public void setUserPrincipal(UserPrincipal userPrincipal) {
        this.userPrincipal = userPrincipal;
    }

    public AuthenticationToken getAuthenticationToken() {
        return authenticationToken;
    }

    public void setAuthenticationToken(AuthenticationToken authenticationToken) {
        this.authenticationToken = authenticationToken;
    }

    public boolean isAuthenticated() {
        return userPrincipal != null;
    }

    public String getPrincipalName() {
        String result;
        if (isAuthenticated()) {
            result = userPrincipal.getName();
        } else {
            result = "[anonymous]";
        }
        return result;
    }

    public void clearAuthenticationInfo() {
        userPrincipal = null;
        authenticationToken = null;
    }
}
