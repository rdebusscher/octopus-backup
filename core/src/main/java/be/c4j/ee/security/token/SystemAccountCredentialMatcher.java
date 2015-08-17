package be.c4j.ee.security.token;

import be.c4j.ee.security.systemaccount.SystemAccountAuthenticationToken;
import be.c4j.ee.security.util.SpecialStateChecker;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;

/**
 *
 */
public class SystemAccountCredentialMatcher implements CredentialsMatcher {
    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        return SpecialStateChecker.isInSystemAccountAuthentication() && token instanceof SystemAccountAuthenticationToken;
    }
}
