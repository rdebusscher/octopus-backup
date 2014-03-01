package be.c4j.ee.security.role;

import org.apache.myfaces.extensions.cdi.core.api.security.AbstractAccessDecisionVoter;
import org.apache.myfaces.extensions.cdi.core.api.security.SecurityViolation;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.subject.Subject;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.interceptor.InvocationContext;
import java.util.Set;

/**
 *
 */
@Typed
public class GenericRoleVoter extends AbstractAccessDecisionVoter {

    @Inject
    private Subject subject;

    private NamedApplicationRole namedRole;

    public void setNamedRole(NamedApplicationRole namedRole) {
        this.namedRole = namedRole;
    }

    @Override
    protected void checkPermission(InvocationContext invocationContext, Set<SecurityViolation> violations) {
        try {
            subject.checkPermission(namedRole);
        } catch (AuthorizationException e) {
            violations.add(newSecurityViolation("TODO : " + namedRole.getRoleName()));
        }

    }
}