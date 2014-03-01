package be.c4j.ee.security.role;

import be.c4j.ee.security.exception.ConfigurationException;
import org.apache.shiro.authz.Permission;

/**
 *
 */
public class NamedApplicationRole implements Permission {

    private String roleName;

    public NamedApplicationRole(String roleName) {
        if (roleName == null || roleName.trim().length() == 0) {
            throw new ConfigurationException("role name can't be null or empty");
        }
        this.roleName = roleName;
    }

    @Override
    public boolean implies(Permission p) {
        // By default only supports comparisons with other NamedApplicationRole
        if (!(p instanceof NamedApplicationRole)) {
            return false;
        }
        NamedApplicationRole otherRole = (NamedApplicationRole) p;
        return roleName.equals(otherRole.roleName);
    }

    public String getRoleName() {
        return roleName;
    }
}
