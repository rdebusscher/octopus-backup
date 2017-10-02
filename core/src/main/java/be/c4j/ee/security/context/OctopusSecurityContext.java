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
package be.c4j.ee.security.context;

import be.c4j.ee.security.PublicAPI;
import be.c4j.ee.security.exception.SystemAccountActivationException;
import be.c4j.ee.security.systemaccount.SystemAccountAuthenticationToken;
import be.c4j.ee.security.systemaccount.SystemAccountPrincipal;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;

import javax.enterprise.context.Dependent;
import java.io.Serializable;

/**
 *
 */
@Dependent  // Because we keep the Shiro Subject for the asynchronous use case.
@PublicAPI
public class OctopusSecurityContext implements Serializable {

    private Subject subject;

    /* Support for Asynchronous calls*/
    public void prepareForAsyncUsage() {
        // TODO Last tests with WildFly 10 suggests that this method is no longer needed, just as the binding of the Subject to the ThreadContext (OctopusInterceptor)
        subject = SecurityUtils.getSubject();
    }

    public Subject getSubject() {
        Subject result = subject;
        if (subject != null) {

            subject = null;  // So that next calls make a anonymous user or the current Subject associated with the thread.
        } else {
            result = SecurityUtils.getSubject();
        }
        return result;
    }

    /*  Support for System accounts */
    public void activateSystemAccount(String systemAccountIdentifier) {
        Subject currentSubject = SecurityUtils.getSubject();
        if (currentSubject.isAuthenticated()) {
            throw new SystemAccountActivationException();
        } else {
            // TODO Do we need to protect this by checking it is from a trusted place?
            SystemAccountPrincipal accountPrincipal = new SystemAccountPrincipal(systemAccountIdentifier);

            SecurityUtils.getSubject().login(new SystemAccountAuthenticationToken(accountPrincipal));
        }

    }

    public void releaseSubject() {
        ThreadContext.unbindSubject();
    }

    public static boolean isSystemAccount(Object principal) {
        return principal instanceof SystemAccountPrincipal;
    }

    /* regular method useable in all cases (JSF + REST) */
    public void logout() {
        SecurityUtils.getSubject().logout();
    }

}