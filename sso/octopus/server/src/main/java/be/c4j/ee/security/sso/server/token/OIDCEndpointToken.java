package be.c4j.ee.security.sso.server.token;

import be.c4j.ee.security.shiro.ValidatedAuthenticationToken;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.apache.shiro.authc.AuthenticationToken;

/**
 *
 */

public class OIDCEndpointToken implements ValidatedAuthenticationToken, AuthenticationToken {


    private ClientAuthentication clientAuthentication;

    public OIDCEndpointToken(ClientAuthentication clientAuthentication) {
        this.clientAuthentication = clientAuthentication;
    }

    public ClientID getClientId() {
        return clientAuthentication.getClientID();
    }

    @Override
    public Object getPrincipal() {
        return getClientId();
    }

    @Override
    public Object getCredentials() {
        return null;
    }
}
