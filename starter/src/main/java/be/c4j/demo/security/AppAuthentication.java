package be.c4j.demo.security;

import be.c4j.ee.security.realm.AuthenticationInfoBuilder;
import be.c4j.ee.security.realm.SecurityDataProvider;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;

import javax.enterprise.context.ApplicationScoped;


@ApplicationScoped
public class AppAuthentication implements SecurityDataProvider {

    private int principalId = 0;

    @Override
    public AuthenticationInfo getAuthenticationInfo(UsernamePasswordToken token) {

        AuthenticationInfoBuilder authenticationInfoBuilder = new AuthenticationInfoBuilder();
        authenticationInfoBuilder.principalId(principalId++).name(token.getPrincipal().toString());
        // TODO: Change for production. Here we use username as password
        authenticationInfoBuilder.password(token.getUsername());

        return authenticationInfoBuilder.build();
    }


    @Override
    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {

        // TODO: Change for production. Principal has no assigned no permission not roles.
        return new SimpleAuthorizationInfo();
    }

}
