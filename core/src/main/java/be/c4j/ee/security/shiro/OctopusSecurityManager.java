package be.c4j.ee.security.shiro;

import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.twostep.TwoStepAuthenticationInfo;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 */
public class OctopusSecurityManager extends DefaultWebSecurityManager {

    private static final Logger log = LoggerFactory.getLogger(OctopusSecurityManager.class);

    private SubjectFactory twoStepSubjectFactory;

    public OctopusSecurityManager() {
        twoStepSubjectFactory = new TwoStepSubjectFactory();
        setSubjectFactory(new OctopusSubjectFactory());
    }

    public Subject login(Subject subject, AuthenticationToken token) throws AuthenticationException {
        AuthenticationInfo info;
        try {
            info = authenticate(token);

        } catch (AuthenticationException ae) {
            try {
                onFailedLogin(token, ae, subject);
            } catch (Exception e) {
                if (log.isInfoEnabled()) {
                    log.info("onFailedLogin method threw an " +
                            "exception.  Logging and propagating original AuthenticationException.", e);
                }
            }
            throw ae; //propagate
        }

        Subject loggedIn;
        if (info instanceof TwoStepAuthenticationInfo) {
            loggedIn = createSubject(token, info, subject);

            onSuccessfulLogin(token, info, loggedIn);

        } else {
            UserPrincipal userPrincipal = (UserPrincipal) info.getPrincipals().getPrimaryPrincipal();

            if (userPrincipal.needsTwoStepAuthentication()) {
                loggedIn = createTwoStepSubject(token, info, subject);

            } else {
                loggedIn = createSubject(token, info, subject);

                onSuccessfulLogin(token, info, loggedIn);

            }
        }
        return loggedIn;
    }

    protected Subject createTwoStepSubject(AuthenticationToken token, AuthenticationInfo info, Subject existing) {
        SubjectContext context = createSubjectContext();
        context.setAuthenticationToken(token);
        context.setAuthenticationInfo(info);
        if (existing != null) {
            context.setSubject(existing);
        }
        return createSubject(context);
    }

    protected Subject doCreateSubject(SubjectContext context) {

        UserPrincipal userPrincipal = getUserPrincipal(context);
        Subject result;
        if (userPrincipal != null && userPrincipal.needsTwoStepAuthentication()) {

            result = twoStepSubjectFactory.createSubject(context);
        } else {

            result = getSubjectFactory().createSubject(context);
        }
        return result;
    }

    private UserPrincipal getUserPrincipal(SubjectContext context) {
        PrincipalCollection principals = null;
        AuthenticationInfo authenticationInfo = context.getAuthenticationInfo();
        if (authenticationInfo != null) {
            principals = authenticationInfo.getPrincipals();
        }
        return principals == null ? null : (UserPrincipal) principals.getPrimaryPrincipal();
    }
}