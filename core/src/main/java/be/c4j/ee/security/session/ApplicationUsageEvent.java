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

public class ApplicationUsageEvent {

    private String sessionId;
    private HttpSession session;
    private UserAction userAction;
    private UserPrincipal userPrincipal;
    private AuthenticationToken authenticationToken;

    public ApplicationUsageEvent(HttpSession session, UserAction userAction) {
        this.session = session;
        this.userAction = userAction;

        sessionId = session.getId();
    }

    public ApplicationUsageEvent(String sessionId, UserPrincipal userPrincipal, AuthenticationToken authenticationToken) {
        this.sessionId = sessionId;
        this.userPrincipal = userPrincipal;
        this.authenticationToken = authenticationToken;
        userAction = UserAction.LOGON;
    }

    public ApplicationUsageEvent(String sessionId) {
        this.sessionId = sessionId;
        userAction = UserAction.LOGOUT;
    }

    public String getSessionId() {
        return sessionId;
    }

    public HttpSession getSession() {
        return session;
    }

    public UserAction getUserAction() {
        return userAction;
    }

    public UserPrincipal getUserPrincipal() {
        return userPrincipal;
    }

    public AuthenticationToken getAuthenticationToken() {
        return authenticationToken;
    }
}
