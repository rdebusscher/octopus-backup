package be.c4j.ee.security.twostep;

/**
 *
 */
public interface TwoStepCredentialsMatcher {

    boolean doTwoStepCredentialsMatch(Object twoStepCredentials);
}
