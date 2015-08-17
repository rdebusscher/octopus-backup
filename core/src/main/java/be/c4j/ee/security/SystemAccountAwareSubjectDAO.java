package be.c4j.ee.security;

import be.c4j.ee.security.context.OctopusSecurityContext;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.subject.Subject;

/**
 *
 */
public class SystemAccountAwareSubjectDAO extends DefaultSubjectDAO {

    @Override
    public Subject save(Subject subject) {
        // SystemAccounts are created manually from OctopusSecurityContext and they aren't correctly linked to the Http environment
        // Also no need to store these.

        if (!OctopusSecurityContext.isSystemAccount(subject.getPrincipal())) {
            return super.save(subject);
        } else {
            return subject;
        }
    }
}
