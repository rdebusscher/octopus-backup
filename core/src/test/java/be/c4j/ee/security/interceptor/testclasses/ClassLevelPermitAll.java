package be.c4j.ee.security.interceptor.testclasses;

import be.c4j.ee.security.interceptor.CallFeedbackCollector;

import javax.annotation.security.PermitAll;

/**
 *
 */
@PermitAll
public class ClassLevelPermitAll {

    public static final String CLASS_LEVEL_PERMIT_ALL = "ClassLevel#permitAll";


    public void permitAll1() {
        CallFeedbackCollector.addCallFeedback(CLASS_LEVEL_PERMIT_ALL);
    }

    public void permitAll2() {
        CallFeedbackCollector.addCallFeedback(CLASS_LEVEL_PERMIT_ALL);
    }

}
