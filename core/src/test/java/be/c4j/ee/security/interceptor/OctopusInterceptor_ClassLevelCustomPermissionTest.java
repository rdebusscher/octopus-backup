package be.c4j.ee.security.interceptor;

import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.interceptor.testclasses.ClassLevelCustomPermission;
import be.c4j.ee.security.permission.GenericPermissionVoter;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.util.ReflectionUtil;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.interceptor.InvocationContext;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
@RunWith(Parameterized.class)
public class OctopusInterceptor_ClassLevelCustomPermissionTest extends OctopusInterceptorTest {

    public OctopusInterceptor_ClassLevelCustomPermissionTest(boolean authenticated, String permission, boolean customAccess) {
        super(authenticated, permission, customAccess);
    }

    @Parameterized.Parameters
    public static List<Object[]> defineScenarios() {
        return Arrays.asList(new Object[][]{
                {NOT_AUTHENTICATED, null, NO_CUSTOM_ACCESS},            //0
                {NOT_AUTHENTICATED, null, CUSTOM_ACCESS},               //1
                {AUTHENTICATED, null, NO_CUSTOM_ACCESS},                //2
                {AUTHENTICATED, PERMISSION1, NO_CUSTOM_ACCESS},        //3
                {AUTHENTICATED, null, CUSTOM_ACCESS},                   //4
        });
    }

    @Test
    public void testInterceptShiroSecurity_customPermission1() throws Exception {

        Object target = new ClassLevelCustomPermission();
        Method method = target.getClass().getMethod("customPermission1");
        InvocationContext context = new TestInvocationContext(target, method);

        performAndCheck(context);
    }

    private void performAndCheck(InvocationContext context) throws Exception {
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
            assertThat(feedback).contains(ClassLevelCustomPermission.CLASS_LEVEL_CUSTOM_PERMISSION);

        } catch (OctopusUnauthorizedException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();

        }
    }

    @Test
    public void testInterceptShiroSecurity_customPermission1Bis() throws Exception {

        Object target = new ClassLevelCustomPermission();
        Method method = target.getClass().getMethod("customPermission1");
        InvocationContext context = new TestInvocationContext(target, method);

        performAndCheck(context);
    }


}

