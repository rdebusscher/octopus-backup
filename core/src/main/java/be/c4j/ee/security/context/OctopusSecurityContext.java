package be.c4j.ee.security.context;

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
            // TODO Do we need to protect this by checking it is from a trusted place.
            SystemAccountPrincipal accountPrincipal = new SystemAccountPrincipal(systemAccountIdentifier);

            ThreadContext.put(SYSTEM_ACCOUNT_AUTHENTICATION, new InSystemAccountAuthentication());
            try {
                SecurityUtils.getSubject().login(new SystemAccountAuthenticationToken(accountPrincipal));
            } finally {
                ThreadContext.remove(SYSTEM_ACCOUNT_AUTHENTICATION);
            }
        }

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