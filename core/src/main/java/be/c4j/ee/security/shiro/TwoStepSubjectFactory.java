package be.c4j.ee.security.shiro;

import be.c4j.ee.security.twostep.TwoStepSubject;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.web.mgt.DefaultWebSubjectFactory;
import org.apache.shiro.web.subject.WebSubjectContext;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 *
 */
public class TwoStepSubjectFactory extends DefaultWebSubjectFactory {

    public Subject createSubject(SubjectContext context) {
        if (!(context instanceof WebSubjectContext)) {
            return super.createSubject(context);
        }
        WebSubjectContext wsc = (WebSubjectContext) context;
        SecurityManager securityManager = wsc.resolveSecurityManager();
        Session session = wsc.resolveSession();
        boolean sessionEnabled = wsc.isSessionCreationEnabled();
        PrincipalCollection principals = wsc.resolvePrincipals();
        String host = wsc.resolveHost();
        ServletRequest request = wsc.resolveServletRequest();
        ServletResponse response = wsc.resolveServletResponse();

        return new TwoStepSubject(principals, host, session, sessionEnabled,
                request, response, securityManager);
    }

}
