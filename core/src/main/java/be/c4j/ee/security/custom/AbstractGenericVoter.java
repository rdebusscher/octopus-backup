package be.c4j.ee.security.custom;

import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import be.c4j.ee.security.util.MethodParameterCheck;
import org.apache.myfaces.extensions.cdi.core.api.security.AbstractAccessDecisionVoter;
import org.apache.myfaces.extensions.cdi.core.api.security.SecurityViolation;

import javax.inject.Inject;
import javax.interceptor.InvocationContext;
import java.util.Set;

/**
 *
 */
public abstract class AbstractGenericVoter extends AbstractAccessDecisionVoter {

    @Inject
    protected MethodParameterCheck methodParameterCheck;

    @Inject
    protected SecurityViolationInfoProducer infoProducer;

    protected void checkMethodHasParameterTypes(Set<SecurityViolation> violations, InvocationContext invocationContext, Class<?>... parameterTypes) {
        SecurityViolation violation = methodParameterCheck.checkMethodHasParameterTypes(invocationContext, parameterTypes);
        if (violation != null) {
            violations.add(violation);
        }
    }
}
