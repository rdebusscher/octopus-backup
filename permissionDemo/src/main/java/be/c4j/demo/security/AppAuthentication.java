package be.c4j.demo.security;

import be.c4j.demo.security.demo.model.Principal;
import be.c4j.demo.security.demo.service.PermissionService;
import be.c4j.demo.security.permission.DemoPermission;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.PermissionLookup;
import be.c4j.ee.security.realm.AuthenticationInfoBuilder;
import be.c4j.ee.security.realm.AuthorizationInfoBuilder;
import be.c4j.ee.security.realm.SecurityDataProvider;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import java.util.List;


@ApplicationScoped
public class AppAuthentication implements SecurityDataProvider {

    @Inject
    private PermissionService permissionService;

    @Override
    public AuthenticationInfo getAuthenticationInfo(UsernamePasswordToken token) {
        Principal principal = permissionService.getPrincipalByUserName(token.getUsername());

        if (principal == null) {
            return null;
        } else {

            AuthenticationInfoBuilder authenticationInfoBuilder = new AuthenticationInfoBuilder();
            authenticationInfoBuilder.principalId(principal.getId()).name(principal.getEmployee().getName());
            authenticationInfoBuilder.password(principal.getPassword()) ;

            authenticationInfoBuilder.addUserInfo(UserInfo.EMPLOYEE_ID, principal.getEmployee().getId());
            if (principal.getEmployee().getDepartment() != null) {

                authenticationInfoBuilder.addUserInfo(UserInfo.DEPARTMENT_ID, principal.getEmployee().getDepartment().getId());
            }

            if (principal.getEmployee().getManager() != null) {
                authenticationInfoBuilder.addUserInfo(UserInfo.MANAGER_EMPLOYEE_ID, principal.getEmployee().getManager().getId());
            }


            return authenticationInfoBuilder.build();
        }
    }


    @Override
    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {

        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();
        builder.addPermissions(permissionService.getPermissionsForPrincipal((UserPrincipal) principals.getPrimaryPrincipal()));

        return builder.build();
    }


    @ApplicationScoped
    @Produces
    public PermissionLookup<DemoPermission> buildLookup() {

        List<NamedDomainPermission> allPermissions = permissionService.getAllPermissions();
        return new PermissionLookup<DemoPermission>(allPermissions, DemoPermission.class);
    }

}
