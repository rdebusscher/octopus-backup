package be.c4j.ee.security.role.filter;

import be.c4j.ee.security.role.NamedRole;
import be.c4j.ee.security.role.RoleLookup;
import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 *
 */
public class NamedRoleFilter extends AuthorizationFilter {

    private RoleLookup<? extends NamedRole> roleLookup;

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws
            Exception {
        Subject subject = getSubject(request, response);
        String[] roles = (String[]) mappedValue;
        checkLookup();

        boolean permitted = true;
        for(String role : roles) {
            if (!subject.isPermitted(roleLookup.getRole(role))) {
                permitted = false;
            }
        }
        return permitted;
    }

    private void checkLookup() {
        // We can't do this in onFilterConfigSet as it is to soon.  Not available at that time
        if (roleLookup == null) {
            roleLookup = CodiUtils.getContextualReferenceByClass(RoleLookup.class);
        }
    }
}
