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
 *
 */
package be.c4j.ee.security.realm;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.permission.PermissionLookup;
import be.c4j.ee.security.permission.StringPermissionLookup;
import be.c4j.ee.security.role.NamedRole;
import be.c4j.ee.security.role.RoleLookup;
import be.c4j.ee.security.util.CDIUtil;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.SimpleAuthorizationInfo;

import javax.enterprise.inject.Typed;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 *
 */
@Typed
public class AuthorizationInfoBuilder {

    private PermissionLookup permissionLookup;

    private StringPermissionLookup stringLookup;

    private RoleLookup roleLookup;

    public AuthorizationInfoBuilder() {
        permissionLookup = CDIUtil.getOptionalBean(PermissionLookup.class);
        stringLookup = CDIUtil.getOptionalBean(StringPermissionLookup.class);
        roleLookup = CDIUtil.getOptionalBean(RoleLookup.class);
    }

    private Set<Permission> permissionsAndRoles = new HashSet<Permission>();

    public AuthorizationInfoBuilder addPermission(NamedPermission namedPermission) {
        if (namedPermission instanceof NamedDomainPermission) {
            permissionsAndRoles.add((NamedDomainPermission) namedPermission);
        } else {
            if (permissionLookup == null && stringLookup == null) {
                throw new OctopusConfigurationException("A @Producer needs to be defined for PermissionLookup or StringPermissionLookup");
            }
            Permission permission = null;
            if (permissionLookup != null) {
                permission = permissionLookup.getPermission(namedPermission.name());
            } else {
                permission = stringLookup.getPermission(namedPermission.name());
            }
            permissionsAndRoles.add(permission);
        }
        return this;
    }

    public AuthorizationInfoBuilder addPermissions(Collection<? extends NamedPermission> namedPermissions) {
        Iterator<? extends NamedPermission> iter = namedPermissions.iterator();
        while (iter.hasNext()) {
            NamedPermission namedPermission = iter.next();
            addPermission(namedPermission);
        }
        return this;
    }

    public AuthorizationInfoBuilder addPermissionAndRoles(Collection<? extends Permission> permissions) {
        permissionsAndRoles.addAll(permissions);
        return this;
    }

    public AuthorizationInfoBuilder addRole(NamedRole namedRole) {
        if (roleLookup == null) {
            throw new OctopusConfigurationException("A @Producer needs to be defined for RoleLookup");
        }

        permissionsAndRoles.add(roleLookup.getRole(namedRole.name()));
        return this;
    }

    public AuthorizationInfoBuilder addRoles(Collection<? extends NamedRole> namedRoles) {
        Iterator<? extends NamedRole> iter = namedRoles.iterator();
        while (iter.hasNext()) {
            NamedRole namedRole = iter.next();
            addRole(namedRole);
        }
        return this;
    }

    public AuthorizationInfo build() {
        SimpleAuthorizationInfo result = new SimpleAuthorizationInfo();
        result.addObjectPermissions(permissionsAndRoles);
        return result;
    }

}
