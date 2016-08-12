package be.c4j.ee.security.salt;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;

/**
 *
 */
public class OctopusHashedCredentialsMatcher extends HashedCredentialsMatcher {

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        if (token instanceof UsernamePasswordToken) {
            return super.doCredentialsMatch(token, info);
        } else {
            return false;
        }
    }
}
