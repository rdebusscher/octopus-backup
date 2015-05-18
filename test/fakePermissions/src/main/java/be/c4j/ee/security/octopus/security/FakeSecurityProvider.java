package be.c4j.ee.security.octopus.security;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.realm.AuthorizationInfoBuilder;
import be.c4j.ee.security.sso.provider.FakePermissionProvider;
import be.c4j.ee.security.sso.provider.SSOClientSecurityProvider;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;

import javax.enterprise.inject.Specializes;
import javax.inject.Inject;
import java.io.Serializable;
import java.util.List;

/**
 *
 */
@Specializes
public class FakeSecurityProvider extends SSOClientSecurityProvider {

    @Inject
    private FakePermissionProvider fakePermissionProvider;

    @Override
    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {
        AuthorizationInfoBuilder authorizationInfoBuilder = new AuthorizationInfoBuilder();
        UserPrincipal primaryPrincipal = (UserPrincipal) principals.getPrimaryPrincipal();
        Serializable localId = primaryPrincipal.getInfo().get(OAuth2User.LOCAL_ID);

        if (!fakePermissionProvider.isFakeLocalId(localId)) {
            return super.getAuthorizationInfo(principals);
        }

        List<NamedPermission> permissions = fakePermissionProvider.getPermissions(localId);

        for (NamedPermission permission : permissions) {
            authorizationInfoBuilder.addPermission(permission);
        }

        return authorizationInfoBuilder.build();
    }
}
