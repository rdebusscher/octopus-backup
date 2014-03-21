package be.c4j.ee.security.exception;

import org.apache.shiro.authc.AuthenticationException;

/**
 *
 */
public class FrameworkConfigurationException extends AuthenticationException {

    public FrameworkConfigurationException(String message) {
        super(message);
    }
}
