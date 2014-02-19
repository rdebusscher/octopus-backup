package be.c4j.ee.security.event;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;

public class LogonEvent {

    private AuthenticationToken token;
    private AuthenticationInfo info;

    public LogonEvent(AuthenticationToken someToken, AuthenticationInfo someInfo) {
        token = someToken;
        info = someInfo;
    }

    public AuthenticationToken getToken() {
        return token;
    }

    public AuthenticationInfo getInfo() {
        return info;
    }

}
