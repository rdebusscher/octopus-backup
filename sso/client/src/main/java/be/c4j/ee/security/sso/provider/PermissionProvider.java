package be.c4j.ee.security.sso.provider;

import be.c4j.ee.security.permission.NamedPermission;

import java.io.Serializable;
import java.util.List;

/**
 *
 */
public interface PermissionProvider {

    List<NamedPermission> getNamedPermissions(Serializable localId);
}
