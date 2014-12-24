package be.c4j.ee.scurity.credentials.authentication.oauth2.google.matcher;

import be.c4j.ee.scurity.credentials.authentication.oauth2.google.GoogleUser;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;

/**
 *
 */
public class GoogleCredentialsMatcher implements CredentialsMatcher {
    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        // When the token is from Google, authentication is already performed
        return token instanceof GoogleUser;
    }
}
