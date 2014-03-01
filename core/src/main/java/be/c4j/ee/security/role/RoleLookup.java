package be.c4j.ee.security.role;

import javax.enterprise.inject.Typed;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 *
 */
@Typed
public class RoleLookup <T extends Enum<T>> {
    private Map<T, NamedApplicationRole> map;  // for holding the mapping between the two

    private Class<T> enumClazz;

    public RoleLookup() {
        // although this bean is excluded, Weld (Glassfish 3.1.2.2) wants it to have a no arg constructor.
    }

    public RoleLookup(List<NamedApplicationRole> allRoles, Class<T> clazz) {
        enumClazz = clazz;
        map = new EnumMap<T, NamedApplicationRole>(clazz);
        // map the lookups together
        for (NamedApplicationRole item : allRoles) {
            T key = Enum.valueOf(clazz, item.getRoleName());
            map.put(key, item);
        }
    }

    public NamedApplicationRole getRole(T roleName) {
        return map.get(roleName);
    }

    public NamedApplicationRole getRole(String roleName) {
        return getRole(Enum.valueOf(enumClazz, roleName));
    }
}

