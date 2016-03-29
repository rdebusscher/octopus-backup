/*
 * Copyright 2014-2016 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.context;

import be.c4j.ee.security.exception.SystemAccountActivationException;
import be.c4j.ee.security.systemaccount.SystemAccountAuthenticationToken;
import be.c4j.ee.security.systemaccount.SystemAccountPrincipal;
import be.c4j.ee.security.util.SpecialStateChecker;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;

import javax.enterprise.context.Dependent;
import java.io.Serializable;

/**
 *
 */
@Dependent
public class OctopusSecurityContext implements Serializable {

    public static final String SYSTEM_ACCOUNT_AUTHENTICATION = "SystemAccountAuthentication";

    private Subject subject;

    public void prepareForAsyncUsage() {
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

    public void activateSystemAccount(String systemAccountIdentifier) {
        Subject subject = SecurityUtils.getSubject();
        if (subject.isAuthenticated()) {
            throw new SystemAccountActivationException();
        } else {
            // TODO Do we need to protect this by checking it is from a trusted place?
            SystemAccountPrincipal accountPrincipal = new SystemAccountPrincipal(systemAccountIdentifier);

            ThreadContext.put(SYSTEM_ACCOUNT_AUTHENTICATION, new InSystemAccountAuthentication());
            try {
                SecurityUtils.getSubject().login(new SystemAccountAuthenticationToken(accountPrincipal));
            } finally {
                ThreadContext.remove(SYSTEM_ACCOUNT_AUTHENTICATION);
            }
        }

    }

    public static void startInSystemAccountAuthentication() {
        if (SpecialStateChecker.isInAuthentication()) {
            ThreadContext.put(SYSTEM_ACCOUNT_AUTHENTICATION, new InSystemAccountAuthentication());
        } else {
            throw new IllegalStateException("InSystemAccountAuthentication can't be started since we aren't within the Authentication process");
        }
    }

    public static void endInSystemAccountAuthentication() {
        ThreadContext.remove(SYSTEM_ACCOUNT_AUTHENTICATION);
    }

    public static boolean isSystemAccount(Object principal) {
        return principal instanceof SystemAccountPrincipal;
    }

    public static final class InSystemAccountAuthentication {
        // So that we only can create this class from this class.
        private InSystemAccountAuthentication() {
        }
    }
}