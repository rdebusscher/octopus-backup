package be.c4j.ee.security.twostep.twilio.matcher;

import be.c4j.ee.security.twostep.TwoStepCredentialsMatcher;

/**
 *
 */
public class SimpleTwoStepMatcher implements TwoStepCredentialsMatcher {

    private Object expected;

    public SimpleTwoStepMatcher(Object expected) {
        this.expected = expected;
    }

    @Override
    public boolean doTwoStepCredentialsMatch(Object twoStepCredentials) {
        return expected.equals(twoStepCredentials);
    }
}
