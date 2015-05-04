package be.c4j.ee.security.interceptor.testclasses;

import be.c4j.ee.security.custom.AbstractGenericVoter;
import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;

import javax.enterprise.context.ApplicationScoped;
import java.util.Set;

/**
 *
 */
@ApplicationScoped
public class TestCustomVoter extends AbstractGenericVoter {

    private boolean customAccess;

    @Override
    protected void checkPermission(AccessDecisionVoterContext accessDecisionVoterContext, Set<SecurityViolation> violations) {
        if (!customAccess) {
            SecurityViolationInfoProducer infoProducer = BeanProvider.getContextualReference(SecurityViolationInfoProducer.class);
            violations.add(newSecurityViolation(infoProducer.getViolationInfo(accessDecisionVoterContext)));
        }
    }

    public void setCustomAccess(boolean customAccess) {
        this.customAccess = customAccess;
    }
}
