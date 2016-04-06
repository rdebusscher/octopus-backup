package be.c4j.ee.security.shiro;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;

/**
 *
 */
public class NoRememberMeManager implements RememberMeManager {
    @Override
    public PrincipalCollection getRememberedPrincipals(SubjectContext subjectContext) {
        return null;
    }

    @Override
    public void forgetIdentity(SubjectContext subjectContext) {

    }

    @Override
    public void onSuccessfulLogin(Subject subject, AuthenticationToken token, AuthenticationInfo info) {

    }

    @Override
    public void onFailedLogin(Subject subject, AuthenticationToken token, AuthenticationException ae) {

    }

    @Override
    public void onLogout(Subject subject) {

    }
}
