package be.c4j.ee.security.event;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;

public class LogonFailureEvent {
    private AuthenticationToken token;
    protected AuthenticationException exception;

    public LogonFailureEvent(AuthenticationToken someToken, AuthenticationException someException) {
        token = someToken;
        exception = someException;
    }

    public AuthenticationToken getToken() {
        return token;
    }

    public AuthenticationException getException() {
        return exception;
    }
}
