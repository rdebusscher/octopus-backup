package be.c4j.ee.security.sso.provider;

import be.c4j.ee.security.permission.NamedPermission;

import java.io.Serializable;
import java.util.List;

/**
 * Used in combination with the fakePermission module.
 */
public interface FakePermissionProvider {

    List<NamedPermission> getPermissions(Serializable localId);
}
