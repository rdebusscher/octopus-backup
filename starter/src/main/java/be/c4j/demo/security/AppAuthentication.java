package be.c4j.demo.security;

import be.c4j.demo.security.permission.StarterPermission;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.PermissionLookup;
import be.c4j.ee.security.realm.AuthenticationProvider;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;


@ApplicationScoped
public class AppAuthentication implements AuthenticationProvider {

    private int principalId = 0;

    @Override
    public SimpleAuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {

        UserPrincipal principal = new UserPrincipal(principalId++, token.getPrincipal().toString());
        // TODO: Change for production. Here we use username as password
        return new SimpleAuthenticationInfo(principal, token.getPrincipal(), "MyApp");
    }


    @Override
    public SimpleAuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {

        // TODO: Change for production. Principal has no assigned no permission not roles.
        return  new SimpleAuthorizationInfo();
    }


    @Produces
    @ApplicationScoped
    public PermissionLookup<StarterPermission> createPermissionLookup() {
        return null;
    }

}
