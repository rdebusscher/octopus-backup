package be.c4j.ee.security.twostep.totp.token;

import org.apache.shiro.authc.AuthenticationToken;

/**
 *
 */
public class TOTPToken implements AuthenticationToken {

    private String totpValue;

    public TOTPToken(String totpValue) {
        this.totpValue = totpValue;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public Object getCredentials() {
        return totpValue;
    }

    @Override
    public String toString() {
        return "TOTP Value";
    }
}
