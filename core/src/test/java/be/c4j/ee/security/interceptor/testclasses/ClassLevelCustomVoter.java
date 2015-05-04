package be.c4j.ee.security.interceptor.testclasses;

import be.c4j.ee.security.custom.CustomVoterCheck;
import be.c4j.ee.security.interceptor.CallFeedbackCollector;

/**
 *
 */
@CustomVoterCheck(TestCustomVoter.class)
public class ClassLevelCustomVoter {

    public static final String CLASS_LEVEL_CUSTOM_VOTER = "ClassLevel#customerVoter";


    public void customVoter1() {
        CallFeedbackCollector.addCallFeedback(CLASS_LEVEL_CUSTOM_VOTER);
    }

    public void customVoter2() {
        CallFeedbackCollector.addCallFeedback(CLASS_LEVEL_CUSTOM_VOTER);
    }

}
