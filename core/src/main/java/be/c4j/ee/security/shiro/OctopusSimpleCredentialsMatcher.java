package be.c4j.ee.security.shiro;

import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;

/**
 *
 */
public class OctopusSimpleCredentialsMatcher extends SimpleCredentialsMatcher {

    @Override
    protected boolean equals(Object tokenCredentials, Object accountCredentials) {
        if (tokenCredentials == null || accountCredentials == null) {
            return false;
        }
        return super.equals(tokenCredentials, accountCredentials);
    }
}
