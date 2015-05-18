package be.c4j.ee.security.sso.provider;

import be.c4j.ee.security.permission.NamedPermission;

/**
 *
 */
public class SimpleNamedPermission implements NamedPermission {

    private String name;

    public SimpleNamedPermission(String name) {
        this.name = name;
    }

    @Override
    public String name() {
        return name;
    }
}
