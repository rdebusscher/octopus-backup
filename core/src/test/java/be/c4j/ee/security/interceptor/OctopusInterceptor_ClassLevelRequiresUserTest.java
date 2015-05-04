package be.c4j.ee.security.interceptor;

import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.interceptor.testclasses.ClassLevelRequiresUser;
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
public class OctopusInterceptor_ClassLevelRequiresUserTest extends OctopusInterceptorTest {

    public OctopusInterceptor_ClassLevelRequiresUserTest(boolean authenticated, String permission, boolean customAccess) {
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
    public void testInterceptShiroSecurity_RequiresUser1() throws Exception {

        Object target = new ClassLevelRequiresUser();
        Method method = target.getClass().getMethod("requiresUser1");
        InvocationContext context = new TestInvocationContext(target, method);

        performAndCheck(context);
    }

    private void performAndCheck(InvocationContext context) throws Exception {
        try {
            octopusInterceptor.interceptShiroSecurity(context);

            assertThat(authenticated).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(ClassLevelRequiresUser.CLASS_LEVEL_REQUIRES_USER);

        } catch (OctopusUnauthorizedException e) {
            assertThat(authenticated).isFalse();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_RequiresUser2() throws Exception {

        Object target = new ClassLevelRequiresUser();
        Method method = target.getClass().getMethod("requiresUser2");
        InvocationContext context = new TestInvocationContext(target, method);

        performAndCheck(context);
    }


}

