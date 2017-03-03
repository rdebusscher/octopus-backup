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

import be.c4j.ee.security.event.LogonEvent;
import be.c4j.ee.security.event.LogoutEvent;
import be.c4j.ee.security.event.RememberMeLogonEvent;
import be.c4j.ee.security.event.SessionTimeoutEvent;
import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.util.WebUtils;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Event;
import javax.enterprise.event.Observes;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class ApplicationUsageController {

    private Map<String, ApplicationUsageInfo> applicationUsage = new HashMap<String, ApplicationUsageInfo>();

    @Inject
    private Event<SessionTimeoutEvent> sessionTimeoutEvent;

    public void onApplicationUsageEvent(@Observes ApplicationUsageEvent event) {
        switch (event.getUserAction()) {

            case FIRST_ACCESS:
                applicationUsage.put(event.getSessionId(), newApplicationUsageInfo(event.getSession()));
                break;
            case LOGON:
                ApplicationUsageInfo applicationUsageInfo = applicationUsage.get(event.getSessionId());
                applicationUsageInfo.setAuthenticationToken(event.getAuthenticationToken());
                applicationUsageInfo.setUserPrincipal(event.getUserPrincipal());
                break;
            case REMEMBER_ME_LOGON:
                HttpSession session = event.getHttpServletRequest().getSession();
                String sessionId = session.getId();

                String remoteHost = event.getHttpServletRequest().getRemoteAddr();
                String userAgent = event.getHttpServletRequest().getHeader("User-Agent");

                // OK, not ideal but we overwrite now the existing information we have.
                // Mainly because the session was created at a time where we don't have access to the ServletRequest (without using some ThreadLocal hacks)

                applicationUsage.put(sessionId, new ApplicationUsageInfo(session, remoteHost, userAgent));

                break;
            case LOGOUT:
                applicationUsage.get(event.getSessionId()).clearAuthenticationInfo();
                break;
            case SESSION_END:
                ApplicationUsageInfo usageInfo = applicationUsage.get(event.getSessionId());
                if (usageInfo.isAuthenticated()) {
                    // When the user explicitly logs out himself, the LOGOUT step is done first and we have here thus anonymous user
                    // So this means there was a HTTPSession timeout
                    sessionTimeoutEvent.fire(new SessionTimeoutEvent(usageInfo.getUserPrincipal()));
                }
                applicationUsage.remove(event.getSessionId());
                break;
            default:
                throw new IllegalArgumentException("UserAction " + event.getUserAction() + " not supported");
        }
    }

    private ApplicationUsageInfo newApplicationUsageInfo(HttpSession session) {
        String remoteHost = null;
        String userAgent = null;
        if (ThreadContext.getSecurityManager() != null) {
            // If the Cookie Manager authenticate a user The SubjectDAO want to store it in the Session
            // And no Subject/Security manager is available at that time.
            // TODO Verify the next 2 comments; There is the OctopusSecurityManager.save() adjustment.
            // What if we use cookie for regular apps (non SSO)?
            // Need the info for the upcoming Session Hijack protection.
            HttpServletRequest httpRequest = WebUtils.getHttpRequest(SecurityUtils.getSubject());
            remoteHost = httpRequest.getRemoteAddr();
            userAgent = httpRequest.getHeader("User-Agent");
        }
        return new ApplicationUsageInfo(session, remoteHost, userAgent);

    }

    public void onLogin(@Observes LogonEvent logonEvent) {
        HttpServletRequest httpRequest = WebUtils.getHttpRequest(SecurityUtils.getSubject());
        // There are also use cases where we have a login() from a REST call with noSessionCreation :)
        if (WebUtils._isSessionCreationEnabled(httpRequest)) {
            onApplicationUsageEvent(new ApplicationUsageEvent(httpRequest.getSession().getId(), logonEvent.getUserPrincipal(), logonEvent.getToken()));
        }
    }

    public void onLoginFromRememberMe(@Observes RememberMeLogonEvent event) {
        HttpServletRequest httpRequest = WebUtils.getHttpRequest(event.getSubject());
        // There are also use cases where we have a login() from a REST call with noSessionCreation :)
        if (WebUtils._isSessionCreationEnabled(httpRequest)) {
            onApplicationUsageEvent(new ApplicationUsageEvent(httpRequest));
        }
    }

    public void onLogout(@Observes LogoutEvent logoutEvent) {
        HttpServletRequest httpRequest = WebUtils.getHttpRequest(SecurityUtils.getSubject());
        // There are also use cases where we have a login() from a REST call with noSessionCreation :)
        if (WebUtils._isSessionCreationEnabled(httpRequest)) {
            onApplicationUsageEvent(new ApplicationUsageEvent(httpRequest.getSession().getId()));
        }
    }

    public void invalidateSession(UserSessionFinder userSessionFinder) {
        for (Map.Entry<String, ApplicationUsageInfo> entry : applicationUsage.entrySet()) {
            if (entry.getValue().isAuthenticated()) {
                if (userSessionFinder.isCorrectPrincipal(entry.getValue().getUserPrincipal())) {
                    entry.getValue().getHttpSession().invalidate();
                }
            }
        }
    }

    public ApplicationUsageInfo getInfo(HttpServletRequest httpRequest) {
        ApplicationUsageInfo result = null;
        if (WebUtils._isSessionCreationEnabled(httpRequest)) {
            String sessionId = httpRequest.getSession().getId();
            result = applicationUsage.get(sessionId);
        }
        return result;
    }

    // Since we don't use Java 8, yet :)
    public interface UserSessionFinder {
        boolean isCorrectPrincipal(UserPrincipal userPrincipal);
    }
}
