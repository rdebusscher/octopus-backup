package be.c4j.ee.security.twostep;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.web.subject.support.WebDelegatingSubject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 *
 */
public class TwoStepSubject extends WebDelegatingSubject {
    public TwoStepSubject(PrincipalCollection principals, String host, Session session, ServletRequest request, ServletResponse response, SecurityManager securityManager) {
        super(principals, false, host, session, request, response, securityManager);
    }

    public TwoStepSubject(PrincipalCollection principals, String host, Session session, boolean sessionEnabled, ServletRequest request, ServletResponse response, SecurityManager securityManager) {
        super(principals, false, host, session, sessionEnabled, request, response, securityManager);
    }
}
