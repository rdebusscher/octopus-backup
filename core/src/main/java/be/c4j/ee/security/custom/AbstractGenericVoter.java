package be.c4j.ee.security.custom;

import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.util.MethodParameterCheck;
import org.apache.myfaces.extensions.cdi.core.api.security.AbstractAccessDecisionVoter;
import org.apache.myfaces.extensions.cdi.core.api.security.SecurityViolation;

import javax.inject.Inject;
import javax.interceptor.InvocationContext;
import javax.servlet.http.HttpServletRequest;
import java.util.Set;

/**
 *
 */
public abstract class AbstractGenericVoter extends AbstractAccessDecisionVoter {

    @Inject
    protected MethodParameterCheck methodParameterCheck;

    @Inject
    protected SecurityViolationInfoProducer infoProducer;

    @Inject
    protected UserPrincipal userPrincipal;

    protected void checkMethodHasParameterTypes(Set<SecurityViolation> violations, InvocationContext invocationContext, Class<?>... parameterTypes) {
        SecurityViolation violation = methodParameterCheck.checkMethodHasParameterTypes(invocationContext, parameterTypes);
        if (violation != null) {
            violations.add(violation);
        }
    }

    protected boolean verifyMethodHasParameterTypes(InvocationContext invocationContext, Class<?>... parameterTypes) {
        SecurityViolation violation = methodParameterCheck.checkMethodHasParameterTypes(invocationContext, parameterTypes);
        return violation == null;
    }

    protected boolean hasServletRequestInfo(InvocationContext invocationContext) {
        SecurityViolation violation = methodParameterCheck.checkMethodHasParameterTypes(invocationContext, HttpServletRequest.class);
        return violation == null;
    }

    protected String getURLRequestParameter(InvocationContext invocationContext, String paramName) {
        HttpServletRequest httpServletRequest = methodParameterCheck.getAssignableParameter(invocationContext, HttpServletRequest.class);
        return httpServletRequest.getParameter(paramName);
    }

    public boolean verify(InvocationContext invocationContext) {
        return checkPermission(invocationContext).isEmpty();
    }
}
