package be.c4j.ee.security.token;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * AuthenticationToken which can be used when insufficient/incorrect data was available on the requestHeader. Used in the OAuth2 and JWT authentication filters.
 */
public class IncorrectDataToken implements AuthenticationToken {

    private String message;

    public IncorrectDataToken(String message) {
        this.message = message;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("IncorrectDataToken{");
        sb.append("message='").append(message).append('\'');
        sb.append('}');
        return sb.toString();
    }
}
