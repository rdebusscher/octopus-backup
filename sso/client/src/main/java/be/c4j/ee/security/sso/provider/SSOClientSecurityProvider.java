package be.c4j.ee.security.sso.provider;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.realm.AuthenticationInfoBuilder;
import be.c4j.ee.security.realm.AuthorizationInfoBuilder;
import be.c4j.ee.security.realm.SecurityDataProvider;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.io.Serializable;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class SSOClientSecurityProvider implements SecurityDataProvider {

    @Inject
    private PermissionProvider permissionProvider;

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
        if (token instanceof OAuth2User) {
            OAuth2User googleUser = (OAuth2User) token;
            AuthenticationInfoBuilder authenticationInfoBuilder = new AuthenticationInfoBuilder();
            authenticationInfoBuilder.principalId(googleUser.getId()).name(googleUser.getFullName());
            authenticationInfoBuilder.addUserInfo(googleUser.getUserInfo());

            authenticationInfoBuilder.addUserInfo(OAuth2User.LOCAL_ID, googleUser.getLocalId());
            return authenticationInfoBuilder.build();

        }
        return null;

    }

    @Override
    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {
        AuthorizationInfoBuilder authorizationInfoBuilder = new AuthorizationInfoBuilder();
        UserPrincipal primaryPrincipal = (UserPrincipal) principals.getPrimaryPrincipal();
        Serializable localId = primaryPrincipal.getInfo().get(OAuth2User.LOCAL_ID);

        List<NamedPermission> permissions = permissionProvider.getNamedPermissions(localId);

        for (NamedPermission permission : permissions) {
            authorizationInfoBuilder.addPermission(permission);
        }

        return authorizationInfoBuilder.build();

    }
}
