package be.c4j.ee.security.context;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

import javax.enterprise.context.Dependent;
import java.io.Serializable;

/**
 *
 */
@Dependent
public class OctopusSecurityContext implements Serializable {

    private Subject subject;

    public void prepareForAsyncUsage() {
        subject = SecurityUtils.getSubject();
    }

    public Subject getSubject() {
        Subject result = subject;
        if (subject != null) {

            subject = null;  // So that next calls make a anonymous user or the current Subject associated with the thread.
        } else {
            result = SecurityUtils.getSubject();
        }
        return result;
    }
}
