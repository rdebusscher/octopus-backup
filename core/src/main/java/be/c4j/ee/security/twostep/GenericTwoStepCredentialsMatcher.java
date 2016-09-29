package be.c4j.ee.security.twostep;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;

/**
 *
 */
public class GenericTwoStepCredentialsMatcher implements CredentialsMatcher {
    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        boolean result = false;
        if (info instanceof TwoStepAuthenticationInfo) {
            TwoStepAuthenticationInfo twoStepAuthenticationInfo = (TwoStepAuthenticationInfo) info;
            TwoStepCredentialsMatcher matcher =  twoStepAuthenticationInfo.getMatcher();
            result = matcher.doTwoStepCredentialsMatch(token.getCredentials());
        }
        return result;
    }
}
