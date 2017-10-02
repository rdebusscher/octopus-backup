/*
 * Copyright 2014-2017 Rudy De Busscher (www.c4j.be)
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
 */
package be.c4j.ee.security.realm;

import be.c4j.ee.security.PublicAPI;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.role.NamedApplicationRole;
import be.c4j.ee.security.role.NamedRole;
import be.c4j.ee.security.role.RoleLookup;
import be.c4j.ee.security.role.SimpleNamedRole;
import be.c4j.ee.security.util.CDIUtil;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.authz.permission.RolePermissionResolver;

import javax.enterprise.inject.Typed;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 *
 */
@Typed
@PublicAPI
public class AuthorizationInfoBuilder {

    private RoleLookup roleLookup;
    private RolePermissionResolver rolePermissionResolver;

    public AuthorizationInfoBuilder() {
        roleLookup = CDIUtil.getOptionalBean(RoleLookup.class);
        rolePermissionResolver = BeanProvider.getContextualReference(RolePermissionResolver.class, true);
    }

    private Set<Permission> permissionsAndRoles = new HashSet<Permission>();
    private Set<String> stringPermissions = new HashSet<String>();

    public AuthorizationInfoBuilder addPermission(NamedPermission namedPermission) {
        if (namedPermission instanceof NamedDomainPermission) {
            permissionsAndRoles.add((NamedDomainPermission) namedPermission);
        } else {
            addPermission(namedPermission.name());
        }
        return this;
    }

    public AuthorizationInfoBuilder addPermission(String permissionName) {
        stringPermissions.add(permissionName);
        return this;
    }

    public AuthorizationInfoBuilder addPermissions(Collection<? extends NamedPermission> namedPermissions) {
        for (NamedPermission namedPermission : namedPermissions) {
            addPermission(namedPermission);
        }
        return this;
    }

    public AuthorizationInfoBuilder addStringPermissions(Collection<String> permissions) {
        stringPermissions.addAll(permissions);
        return this;
    }

    public AuthorizationInfoBuilder addPermissionAndRoles(Collection<? extends Permission> permissions) {
        permissionsAndRoles.addAll(permissions);
        return this;
    }

    public AuthorizationInfoBuilder addRole(NamedRole namedRole) {
        boolean resolved = false;
        if (rolePermissionResolver != null) {
            Collection<Permission> permissions = rolePermissionResolver.resolvePermissionsInRole(namedRole.name());
            if (permissions != null && !permissions.isEmpty()) {
                permissionsAndRoles.addAll(permissions);
                resolved = true;
            }
        }

        if (!resolved) {
            if (roleLookup == null) {
                // No roleLookup specified, use the default logic.
                permissionsAndRoles.add(new NamedApplicationRole(namedRole.name()));
            } else {
                permissionsAndRoles.add(roleLookup.getRole(namedRole.name()));
            }
        }

        return this;
    }

    public AuthorizationInfoBuilder addRoles(Collection<? extends NamedRole> namedRoles) {
        for (NamedRole namedRole : namedRoles) {
            addRole(namedRole);
        }
        return this;
    }

    public AuthorizationInfoBuilder addRolesByName(Collection<String> rolesNames) {
        for (String roleName : rolesNames) {
            addRole(new SimpleNamedRole(roleName));
        }
        return this;
    }

    public AuthorizationInfo build() {
        SimpleAuthorizationInfo result = new SimpleAuthorizationInfo();
        result.addObjectPermissions(permissionsAndRoles);
        result.addStringPermissions(stringPermissions);
        return result;
    }

}
