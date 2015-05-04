package be.c4j.ee.security.interceptor.testclasses;

import be.c4j.ee.security.custom.CustomVoterCheck;
import be.c4j.ee.security.interceptor.CallFeedbackCollector;
import be.c4j.ee.security.realm.OnlyDuringAuthentication;
import be.c4j.ee.security.realm.OnlyDuringAuthorization;
import org.apache.shiro.authz.annotation.RequiresUser;

import javax.annotation.security.PermitAll;

/**
 *
 */
public class MethodLevel {

    public static final String METHOD_LEVEL_PERMIT_ALL = "MethodLevel#permitAll";
    public static final String METHOD_LEVEL_REQUIRES_USER = "MethodLevel#requiresUser";
    public static final String METHOD_LEVEL_IN_AUTHENTICATION = "MethodLevel#inAuthentication";
    public static final String METHOD_LEVEL_IN_AUTHORIZATION = "MethodLevel#inAuthorization";
    public static final String METHOD_LEVEL_PERMISSION1 = "MethodLevel#permission1";
    public static final String METHOD_LEVEL_PERMISSION2 = "MethodLevel#permission2";
    public static final String METHOD_LEVEL_CUSTOM_VOTER = "MethodLevel#customVoter";

    @PermitAll
    public void permitAll() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_PERMIT_ALL);
    }

    public void noAnnotation() {
        CallFeedbackCollector.addCallFeedback("MethodLevel#noAnnotation");
    }

    @RequiresUser
    public void requiresUser() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_REQUIRES_USER);
    }

    @OnlyDuringAuthentication
    public void inAuthentication() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_IN_AUTHENTICATION);
    }

    @OnlyDuringAuthorization
    public void inAuthorization() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_IN_AUTHORIZATION);
    }

    @TestPermissionCheck(TestPermission.PERMISSION1)
    public void permission1() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_PERMISSION1);
    }

    @TestPermissionCheck(TestPermission.PERMISSION2)
    public void permission2() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_PERMISSION2);
    }

    @CustomVoterCheck(TestCustomVoter.class)
    public void customVoter() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_CUSTOM_VOTER);
    }

}
