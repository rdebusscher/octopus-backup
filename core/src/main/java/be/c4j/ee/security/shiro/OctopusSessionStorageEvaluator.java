package be.c4j.ee.security.shiro;

import be.c4j.ee.security.systemaccount.SystemAccountPrincipal;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.mgt.DefaultWebSessionStorageEvaluator;

/**
 *
 */

public class OctopusSessionStorageEvaluator extends DefaultWebSessionStorageEvaluator {

    @Override
    public boolean isSessionStorageEnabled(Subject subject) {
        boolean result;
        if (subject.getPrincipal() instanceof SystemAccountPrincipal) {
            result = false;
        } else {
            result = super.isSessionStorageEnabled(subject);
        }
        return result;
    }
}
