package be.c4j.ee.security.permission;

import be.c4j.ee.security.interceptor.testclasses.TestPermission;
import be.c4j.test.util.BeanManagerFake;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public final class PermissionLookupFixture {

    public static void registerPermissionLookup(BeanManagerFake beanManagerFake) {
        List<NamedDomainPermission> allPermissions = new ArrayList<NamedDomainPermission>();
        allPermissions.add(new NamedDomainPermission("PERMISSION1", "Permission:1:*"));
        allPermissions.add(new NamedDomainPermission("PERMISSION2", "Permission:2:*"));
        allPermissions.add(new NamedDomainPermission("PERMISSION3", "Permission:3:*"));
        PermissionLookup permissionLookup = new PermissionLookup<TestPermission>(allPermissions, TestPermission.class);
        beanManagerFake.registerBean(permissionLookup, PermissionLookup.class);
    }


}