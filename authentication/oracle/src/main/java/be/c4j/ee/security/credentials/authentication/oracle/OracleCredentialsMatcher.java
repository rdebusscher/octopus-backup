package be.c4j.ee.security.credentials.authentication.oracle;

import be.rubus.web.jerry.provider.BeanProvider;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;

/**
 *
 */
public class OracleCredentialsMatcher implements CredentialsMatcher {


    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        if (token instanceof UsernamePasswordToken) {
            OraclePasswordExecutor passwordExecutor = BeanProvider.getContextualReference(OraclePasswordExecutor.class);
            UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;
            return passwordExecutor.checkPassword(usernamePasswordToken.getUsername(), String.valueOf(usernamePasswordToken.getPassword()));
        } else {
            // FIXME logging
            return false;
        }
    }
}
