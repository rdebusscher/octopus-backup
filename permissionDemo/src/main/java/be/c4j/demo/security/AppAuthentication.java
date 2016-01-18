/*
 * Copyright 2014-2016 Rudy De Busscher (www.c4j.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
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
import org.apache.shiro.authc.AuthenticationToken;
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
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
        if (!(token instanceof UsernamePasswordToken)) {
            return null;
        }
        UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;
        Principal principal = permissionService.getPrincipalByUserName(usernamePasswordToken.getUsername());

        if (principal == null) {
            return null;
        } else {

            AuthenticationInfoBuilder authenticationInfoBuilder = new AuthenticationInfoBuilder();
            authenticationInfoBuilder.principalId(principal.getId()).name(principal.getEmployee().getName());
            authenticationInfoBuilder.userName(usernamePasswordToken.getUsername());
            authenticationInfoBuilder.password(principal.getPassword());

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
