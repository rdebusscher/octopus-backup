package be.c4j.ee.security.systemaccount;

import org.apache.shiro.authc.AuthenticationToken;

/**
 *
 */
public class SystemAccountAuthenticationToken implements AuthenticationToken {

    private SystemAccountPrincipal principal;

    public SystemAccountAuthenticationToken(SystemAccountPrincipal principal) {
        this.principal = principal;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public Object getCredentials() {
        return null;
    }
}
