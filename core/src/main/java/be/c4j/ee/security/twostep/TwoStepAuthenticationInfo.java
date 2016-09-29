package be.c4j.ee.security.twostep;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.subject.PrincipalCollection;

/**
 *
 */
public class TwoStepAuthenticationInfo implements AuthenticationInfo {

    private TwoStepCredentialsMatcher matcher;


    public TwoStepAuthenticationInfo(TwoStepCredentialsMatcher matcher) {
        this.matcher = matcher;
    }

    public TwoStepCredentialsMatcher getMatcher() {
        return matcher;
    }

    @Override
    public PrincipalCollection getPrincipals() {
        return null;
    }

    @Override
    public Object getCredentials() {
        return null;
    }
}
