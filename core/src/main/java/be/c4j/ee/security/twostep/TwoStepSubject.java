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
package be.c4j.ee.security.twostep;

import be.c4j.ee.security.shiro.OctopusDelegatingSubject;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.HostAuthenticationToken;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionException;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.DelegatingSubject;
import org.apache.shiro.web.subject.support.WebDelegatingSubject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 *
 */
public class TwoStepSubject extends WebDelegatingSubject {

    private static final Logger log = LoggerFactory.getLogger(TwoStepSubject.class);

    private static final String RUN_AS_PRINCIPALS_SESSION_KEY =
            OctopusDelegatingSubject.class.getName() + ".RUN_AS_PRINCIPALS_SESSION_KEY";

    public TwoStepSubject(PrincipalCollection principals, String host, Session session, ServletRequest request, ServletResponse response, SecurityManager securityManager) {
        super(principals, false, host, session, request, response, securityManager);
    }

    public TwoStepSubject(PrincipalCollection principals, String host, Session session, boolean sessionEnabled, ServletRequest request, ServletResponse response, SecurityManager securityManager) {
        super(principals, false, host, session, sessionEnabled, request, response, securityManager);
    }

    @Override
    public boolean isRemembered() {
        // Default return true when there is a Principal which is not authenticated
        // But we have here the situaton that a TwoStepSubject is not yet fully authenticated
        // and thus we can't grant it remembered (would allow it access by the (Octopus)UserFilter
        return false;
    }

    @Override
    public void login(AuthenticationToken token) throws AuthenticationException {
        clearRunAsIdentitiesInternal();
        Subject subject = securityManager.login(this, token);

        PrincipalCollection principals;

        String host = null;

        if (subject instanceof DelegatingSubject) {
            DelegatingSubject delegating = (DelegatingSubject) subject;
            //we have to do this in case there are assumed identities - we don't want to lose the 'real' principals:
            principals = delegating.getPrincipals();
            host = delegating.getHost();
        } else {
            principals = subject.getPrincipals();
        }

        if (principals == null || principals.isEmpty()) {
            String msg = "Principals returned from securityManager.login( token ) returned a null or " +
                    "empty value.  This value must be non null and populated with one or more elements.";
            throw new IllegalStateException(msg);
        }
        this.principals = principals;
        this.authenticated = subject.isAuthenticated();  // This is the only change !!
        // FIXME We have now a lot of overwritten Shiro code for small changed.
        // Consider integrating Shiro into Octopus.
        if (token instanceof HostAuthenticationToken) {
            host = ((HostAuthenticationToken) token).getHost();
        }
        if (host != null) {
            this.host = host;
        }
        Session session = subject.getSession(false);
        if (session != null) {
            this.session = decorate(session);
        } else {
            this.session = null;
        }

    }

    // The following 2 methods are alos copied since they have private signature
    private void clearRunAsIdentitiesInternal() {
        //try/catch added for SHIRO-298
        try {
            clearRunAsIdentities();
        } catch (SessionException se) {
            log.debug("Encountered session exception trying to clear 'runAs' identities during logout.  This " +
                    "can generally safely be ignored.", se);
        }
    }

    private void clearRunAsIdentities() {
        Session session = getSession(false);
        if (session != null) {
            session.removeAttribute(RUN_AS_PRINCIPALS_SESSION_KEY);
        }
    }

}
