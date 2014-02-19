package be.c4j.ee.security.shiro;

import be.c4j.ee.security.permission.NamedPermission;
import org.apache.shiro.config.Ini;

import javax.enterprise.context.Dependent;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Dependent
public class URLPermissionProtector {

    private Ini.Section section;

    public void addURLs() {

    }

    protected void addSecuredURL(String url, NamedPermission namedPermission) {
        section.put(url, "user, np[" + namedPermission.name() + "]");
    }

    protected void addSecuredURL(String url, Set<NamedPermission> namedPermissions) {
        StringBuilder value = new StringBuilder();
        boolean first = true;
        value.append("user, np[");
        for (NamedPermission permission : namedPermissions) {
            if (!first) {
                value.append(',');
            }
            value.append(permission.name());
            first = false;
        }
        section.put(url, value.toString());
    }

    protected void addSecuredURL(String url, NamedPermission... namedPermissions) {
        addSecuredURL(url, new HashSet<NamedPermission>(Arrays.asList(namedPermissions)));
    }

    public void configurePermissions(Ini.Section section) {
        this.section = section;
        addURLs();
    }

}
