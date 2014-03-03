package be.c4j.ee.security.realm;

import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.permission.PermissionLookup;
import be.c4j.ee.security.role.NamedRole;
import be.c4j.ee.security.role.RoleLookup;
import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;
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

    private RoleLookup roleLookup;

    public AuthorizationInfoBuilder() {
        permissionLookup = CodiUtils.getContextualReferenceByClass(PermissionLookup.class);
        roleLookup = CodiUtils.getContextualReferenceByClass(RoleLookup.class);
    }

    private Set<Permission> permissionsAndRoles = new HashSet<Permission>();

    public AuthorizationInfoBuilder addPermission(NamedPermission namedPermission) {
        permissionsAndRoles.add(permissionLookup.getPermission(namedPermission.name()));
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
