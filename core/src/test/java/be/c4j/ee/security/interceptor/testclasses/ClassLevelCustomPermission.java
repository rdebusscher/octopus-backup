package be.c4j.ee.security.interceptor.testclasses;

import be.c4j.ee.security.interceptor.CallFeedbackCollector;

/**
 *
 */
@TestPermissionCheck(TestPermission.PERMISSION1)
public class ClassLevelCustomPermission {

    public static final String CLASS_LEVEL_CUSTOM_PERMISSION = "ClassLevel#inPermission";


    public void customPermission1() {
        CallFeedbackCollector.addCallFeedback(CLASS_LEVEL_CUSTOM_PERMISSION);
    }

    public void customPermission1Bis() {
        CallFeedbackCollector.addCallFeedback(CLASS_LEVEL_CUSTOM_PERMISSION);
    }

}
