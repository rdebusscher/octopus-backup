package be.c4j.ee.security.credentials.authentication.cas;

import org.apache.shiro.authc.AuthenticationException;

/**
 *
 */
public class CasAuthenticationException extends AuthenticationException {

    public CasAuthenticationException(Throwable cause) {
        super(cause);
    }
}
