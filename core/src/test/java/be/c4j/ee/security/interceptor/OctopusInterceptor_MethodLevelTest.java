package be.c4j.ee.security.interceptor;

import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.interceptor.testclasses.MethodLevel;
import be.c4j.ee.security.permission.GenericPermissionVoter;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.realm.OctopusRealm;
import be.c4j.util.ReflectionUtil;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.interceptor.InvocationContext;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;

/**
 *
 */
@RunWith(Parameterized.class)
public class OctopusInterceptor_MethodLevelTest extends OctopusInterceptorTest {

    public OctopusInterceptor_MethodLevelTest(boolean authenticated, String permission, boolean customAccess) {
        super(authenticated, permission, customAccess);
    }

    @Parameterized.Parameters
    public static List<Object[]> balanceRates() {
        return Arrays.asList(new Object[][]{
                {NOT_AUTHENTICATED, null, NO_CUSTOM_ACCESS},            //0
                {NOT_AUTHENTICATED, null, CUSTOM_ACCESS},               //1
                {AUTHENTICATED, null, NO_CUSTOM_ACCESS},                //2
                {AUTHENTICATED, PERMISSION1, NO_CUSTOM_ACCESS},         //3
                {AUTHENTICATED, null, CUSTOM_ACCESS},                   //4
        });
    }

    @Test
    public void testInterceptShiroSecurity_PermitAll() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("permitAll");
        InvocationContext context = new TestInvocationContext(target, method);

        octopusInterceptor.interceptShiroSecurity(context);

        List<String> feedback = CallFeedbackCollector.getCallFeedback();
        assertThat(feedback).hasSize(1);
        assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_PERMIT_ALL);
    }

    @Test(expected = OctopusUnauthorizedException.class)
    public void testInterceptShiroSecurity_NoAnnotation() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("noAnnotation");
        InvocationContext context = new TestInvocationContext(target, method);

        try {
            octopusInterceptor.interceptShiroSecurity(context);
        } finally {
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_RequiresUser() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("requiresUser");
        InvocationContext context = new TestInvocationContext(target, method);

        try {
            octopusInterceptor.interceptShiroSecurity(context);

            assertThat(authenticated).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_REQUIRES_USER);

        } catch (OctopusUnauthorizedException e) {
            assertThat(authenticated).isFalse();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_InAuthentication() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("inAuthentication");
        InvocationContext context = new TestInvocationContext(target, method);

        // The in Authentication is so encapsulated that we can never set it outside the class (as we could manipulate then the security)
        // That is also the reason we have to simulate a larger part to test this.

        OctopusRealm octopusRealm = new OctopusRealm();
        ReflectionUtil.injectDependencies(octopusRealm, new TestSecurityDataProvider(context));

        try {
            octopusRealm.getAuthenticationInfo(null);

            assertThat(authenticated).isFalse();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_IN_AUTHENTICATION);

        } catch (OctopusUnauthorizedException e) {
            assertThat(authenticated).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_InAuthenticationDirect() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("inAuthentication");
        InvocationContext context = new TestInvocationContext(target, method);


        try {
            octopusInterceptor.interceptShiroSecurity(context);

            fail("We shouldn't be able to call the inAuthentication method as we aren't in the process of such an authentication");

        } catch (OctopusUnauthorizedException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_InAuthorization() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("inAuthorization");
        InvocationContext context = new TestInvocationContext(target, method);

        // The in Authorization is so encapsulated that we can never set it outside the class (as we could manipulate then the security)
        // That is also the reason we have to simulate a larger part to test this.

        OctopusRealm octopusRealm = new OctopusRealm();
        octopusRealm.setCachingEnabled(false);
        ReflectionUtil.injectDependencies(octopusRealm, new TestSecurityDataProvider(context));

        try {
            octopusRealm.checkPermission(new SimplePrincipalCollection(), AUTHORIZATION_PERMISSION);

            assertThat(authenticated).isFalse();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_IN_AUTHORIZATION);

        } catch (OctopusUnauthorizedException e) {
            assertThat(authenticated).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_InAuthorizationDirect() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("inAuthorization");
        InvocationContext context = new TestInvocationContext(target, method);


        try {
            octopusInterceptor.interceptShiroSecurity(context);

            fail("We shouldn't be able to call the inAuthorization method as we aren't in the process of such an authorization");

        } catch (OctopusUnauthorizedException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }


    @Test
    public void testInterceptShiroSecurity_CustomPermissionAnnotation() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("permission1");
        InvocationContext context = new TestInvocationContext(target, method);

        GenericPermissionVoter permissionVoter = new GenericPermissionVoter();
        NamedDomainPermission namedPermission = getNamedDomainPermission(PERMISSION1);
        ReflectionUtil.injectDependencies(permissionVoter, subjectMock, namedPermission);

        beanManagerFake.registerBean("permission1PermissionVoter", permissionVoter);
        beanManagerFake.endRegistration();

        try {
            octopusInterceptor.interceptShiroSecurity(context);

            assertThat(permission).isEqualTo(PERMISSION1);
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_PERMISSION1);

        } catch (OctopusUnauthorizedException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();

        }
    }

    @Test
    public void testInterceptShiroSecurity_CustomPermissionAnnotation2() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("permission2");
        InvocationContext context = new TestInvocationContext(target, method);

        GenericPermissionVoter permissionVoter = new GenericPermissionVoter();
        NamedDomainPermission namedPermission = getNamedDomainPermission(PERMISSION2);
        ReflectionUtil.injectDependencies(permissionVoter, subjectMock, namedPermission);

        beanManagerFake.registerBean("permission2PermissionVoter", permissionVoter);
        beanManagerFake.endRegistration();

        try {
            octopusInterceptor.interceptShiroSecurity(context);

            assertThat(permission).isEqualTo(PERMISSION2);
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_PERMISSION2);

        } catch (OctopusUnauthorizedException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();

        }
    }

    @Test
    public void testInterceptShiroSecurity_CustomVoter() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("customVoter");
        InvocationContext context = new TestInvocationContext(target, method);

        beanManagerFake.endRegistration();

        try {
            octopusInterceptor.interceptShiroSecurity(context);

            assertThat(customAccess).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_CUSTOM_VOTER);

        } catch (OctopusUnauthorizedException e) {

            assertThat(customAccess).isFalse();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();

        }
    }


}

