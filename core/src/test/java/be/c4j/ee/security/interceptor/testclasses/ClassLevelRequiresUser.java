package be.c4j.ee.security.interceptor.testclasses;

import be.c4j.ee.security.interceptor.CallFeedbackCollector;
import org.apache.shiro.authz.annotation.RequiresUser;

/**
 *
 */
@RequiresUser
public class ClassLevelRequiresUser {

    public static final String CLASS_LEVEL_REQUIRES_USER = "ClassLevel#requiresUser";


    public void requiresUser1() {
        CallFeedbackCollector.addCallFeedback(CLASS_LEVEL_REQUIRES_USER);
    }

    public void requiresUser2() {
        CallFeedbackCollector.addCallFeedback(CLASS_LEVEL_REQUIRES_USER);
    }

}
