package be.c4j.ee.security.permission.filter;

import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.permission.PermissionLookup;
import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class NamedPermissionFilter extends AuthorizationFilter {

    private PermissionLookup<? extends NamedPermission> permissionLookup;

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws
            Exception {
        Subject subject = getSubject(request, response);
        String[] permissions = (String[]) mappedValue;
        checkLookup();

        boolean permitted = true;
        for(String permissionName : permissions) {
            if (!subject.isPermitted(permissionLookup.getPermission(permissionName))) {
                permitted = false;
            }
        }
        return permitted;
    }

    private void checkLookup() {
        // We can't do this in onFilterConfigSet as it is to soon.  Not available at that time
        if (permissionLookup == null) {
            permissionLookup = CodiUtils.getContextualReferenceByClass(PermissionLookup.class);
        }
    }
}
