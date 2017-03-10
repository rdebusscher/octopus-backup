package be.c4j.ee.security.sso.server.token;

import be.c4j.ee.security.realm.AuthenticationInfoBuilder;
import be.c4j.ee.security.realm.OctopusDefinedAuthenticationInfo;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;

import javax.enterprise.context.ApplicationScoped;

/**
 * Describe in this block the functionality of the class.
 * Created by rubus on 10/03/17.
 */
@ApplicationScoped
public class InfoForOIDCEndpointToken implements OctopusDefinedAuthenticationInfo {


    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
        if (token instanceof OIDCEndpointToken) {
            OIDCEndpointToken oidcEndpointToken = (OIDCEndpointToken) token;
            AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();
            builder.userName(oidcEndpointToken.getClientId().getValue())
                    .principalId(oidcEndpointToken.getClientId().getValue());
            return builder.build();
        }
        return null;
    }
}
