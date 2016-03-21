package be.c4j.ee.security.permission;

import be.c4j.test.util.BeanManagerFake;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public class StringPermissionLookupFixture {

    public static void registerLookup(BeanManagerFake beanManagerFake) {
        List<NamedDomainPermission> allPermissions = new ArrayList<NamedDomainPermission>();
        allPermissions.add(new NamedDomainPermission("permission1", "SPermission:1:*"));
        allPermissions.add(new NamedDomainPermission("permission2", "SPermission:2:*"));
        allPermissions.add(new NamedDomainPermission("permission3", "SPermission:3:*"));
        StringPermissionLookup stringLookup = new StringPermissionLookup(allPermissions);
        beanManagerFake.registerBean(stringLookup, StringPermissionLookup.class);
    }

}