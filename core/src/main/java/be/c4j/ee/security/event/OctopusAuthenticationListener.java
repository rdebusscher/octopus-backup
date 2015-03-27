/*
 * Copyright 2014-2015 Rudy De Busscher (www.c4j.be)
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
 *
 */
package be.c4j.ee.security.event;

import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationListener;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.PrincipalCollection;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Event;
import javax.inject.Inject;

@ApplicationScoped
public class OctopusAuthenticationListener implements AuthenticationListener {

    @Inject
    private Event<LogonEvent> logonEvent;

    @Inject
    private Event<LogonFailureEvent> logonFailureEvent;

    @Inject
    private Event<LogoutEvent> logoutEvent;

    @Override
    public void onSuccess(AuthenticationToken token, AuthenticationInfo info) {
        LogonEvent event = new LogonEvent(token, info);
        logonEvent.fire(event);
    }

    @Override
    public void onFailure(AuthenticationToken token, AuthenticationException ae) {
        LogonFailureEvent event = new LogonFailureEvent(token, ae);
        logonFailureEvent.fire(event);
    }

    @Override
    public void onLogout(PrincipalCollection principals) {
        LogoutEvent event = new LogoutEvent((UserPrincipal) principals.getPrimaryPrincipal());
        logoutEvent.fire(event);
    }
}
