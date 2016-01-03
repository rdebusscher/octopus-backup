/*
 * Copyright 2014-2015 Rudy De Busscher (www.c4j.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package be.c4j.ee.security.interceptor;

import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.interceptor.testclasses.MethodLevelOverride;
import be.c4j.ee.security.permission.GenericPermissionVoter;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.realm.OctopusRealm;
import be.c4j.util.ReflectionUtil;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.Mockito;

import javax.interceptor.InvocationContext;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(Parameterized.class)
public class OctopusInterceptor_MethodLevelOverrideTest extends OctopusInterceptorTest {

    public OctopusInterceptor_MethodLevelOverrideTest(boolean authenticated, String permission, boolean customAccess, String shiroPermission, String systemAccount) {
        super(authenticated, permission, customAccess, shiroPermission, systemAccount);
    }

    @Parameterized.Parameters
    public static List<Object[]> defineScenarios() {
        return Arrays.asList(new Object[][]{
                {NOT_AUTHENTICATED, null, NO_CUSTOM_ACCESS, null, null},            //0
                {NOT_AUTHENTICATED, null, CUSTOM_ACCESS, null, null},               //1
                {AUTHENTICATED, null, NO_CUSTOM_ACCESS, null, null},                //2
                {AUTHENTICATED, PERMISSION1, NO_CUSTOM_ACCESS, null, null},        //3
                {AUTHENTICATED, null, CUSTOM_ACCESS, null, null},                   //4
                {AUTHENTICATED, null, NO_CUSTOM_ACCESS, SHIRO1, null},            //5
                {AUTHENTICATED, null, NO_CUSTOM_ACCESS, null, ACCOUNT1},                       //6
        });
    }

    @Test
    public void testInterceptShiroSecurity_NoAnnotation() throws Exception {

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("noAnnotation");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        octopusInterceptor.interceptShiroSecurity(context);

        List<String> feedback = CallFeedbackCollector.getCallFeedback();
        assertThat(feedback).hasSize(1);
        assertThat(feedback).contains(MethodLevelOverride.METHOD_LEVEL_NO_ANNOTATION);
    }

    @Test
    public void testInterceptShiroSecurity_RequiresUser() throws Exception {

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("requiresUser");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptShiroSecurity(context);

            assertThat(authenticated).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevelOverride.METHOD_LEVEL_REQUIRES_USER);

        } catch (OctopusUnauthorizedException e) {
            assertThat(authenticated).isFalse();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_InAuthentication() throws Exception {

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("inAuthentication");
        InvocationContext context = new TestInvocationContext(target, method);

        // The in Authentication is so encapsulated that we can never set it outside the class (as we could manipulate then the security)
        // That is also the reason we have to simulate a larger part to test this.

        OctopusRealm octopusRealm = new OctopusRealm();
        OctopusConfig octopusConfigMock = Mockito.mock(OctopusConfig.class);
        when(octopusConfigMock.getHashAlgorithmName()).thenReturn("");
        ReflectionUtil.injectDependencies(octopusRealm, new TestSecurityDataProvider(context), octopusConfigMock);

        finishCDISetup();

        try {
            octopusRealm.getAuthenticationInfo(null);

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevelOverride.METHOD_LEVEL_IN_AUTHENTICATION);

        } catch (OctopusUnauthorizedException e) {
            assertThat(authenticated).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_InAuthenticationDirect() throws Exception {

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("inAuthentication");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

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

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("inAuthorization");
        InvocationContext context = new TestInvocationContext(target, method);

        // The in Authorization is so encapsulated that we can never set it outside the class (as we could manipulate then the security)
        // That is also the reason we have to simulate a larger part to test this.

        OctopusRealm octopusRealm = new OctopusRealm();
        octopusRealm.setCachingEnabled(false);
        ReflectionUtil.injectDependencies(octopusRealm, new TestSecurityDataProvider(context));

        finishCDISetup();

        try {
            octopusRealm.checkPermission(new SimplePrincipalCollection(), AUTHORIZATION_PERMISSION);

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevelOverride.METHOD_LEVEL_IN_AUTHORIZATION);

        } catch (OctopusUnauthorizedException e) {
            assertThat(authenticated).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_InAuthorizationDirect() throws Exception {

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("inAuthorization");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

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

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("permission1");
        InvocationContext context = new TestInvocationContext(target, method);

        GenericPermissionVoter permissionVoter = new GenericPermissionVoter();
        NamedDomainPermission namedPermission = getNamedDomainPermission(PERMISSION1);
        ReflectionUtil.injectDependencies(permissionVoter, subjectMock, namedPermission);

        beanManagerFake.registerBean("permission1PermissionVoter", permissionVoter);

        finishCDISetup();

        try {
            octopusInterceptor.interceptShiroSecurity(context);

            assertThat(permission).isEqualTo(PERMISSION1);
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevelOverride.METHOD_LEVEL_PERMISSION1);

        } catch (OctopusUnauthorizedException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();

        }
    }

    @Test
    public void testInterceptShiroSecurity_CustomPermissionAnnotation2() throws Exception {

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("permission2");
        InvocationContext context = new TestInvocationContext(target, method);

        GenericPermissionVoter permissionVoter = new GenericPermissionVoter();
        NamedDomainPermission namedPermission = getNamedDomainPermission(PERMISSION2);
        ReflectionUtil.injectDependencies(permissionVoter, subjectMock, namedPermission);

        beanManagerFake.registerBean("permission2PermissionVoter", permissionVoter);

        finishCDISetup();

        try {
            octopusInterceptor.interceptShiroSecurity(context);

            assertThat(permission).isEqualTo(PERMISSION2);
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevelOverride.METHOD_LEVEL_PERMISSION2);

        } catch (OctopusUnauthorizedException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();

        }
    }

    @Test
    public void testInterceptShiroSecurity_CustomVoter() throws Exception {

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("customVoter");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptShiroSecurity(context);

            assertThat(customAccess).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevelOverride.METHOD_LEVEL_CUSTOM_VOTER);

        } catch (OctopusUnauthorizedException e) {

            assertThat(customAccess).isFalse();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();

        }
    }

    @Test
    public void testInterceptShiroSecurity_RequiresPermission1() throws Exception {

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("requiresPermission1");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptShiroSecurity(context);

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevelOverride.METHOD_LEVEL_REQUIRES_PERMISSION1);

            assertThat(shiroPermission).isEqualTo(SHIRO1);

        } catch (OctopusUnauthorizedException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_RequiresPermission2() throws Exception {

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("requiresPermission2");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptShiroSecurity(context);

            fail("In our test, subject has never shiro 2 permission");
        } catch (OctopusUnauthorizedException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_SystemAccount1() throws Exception {

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("systemAccountValue1");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptShiroSecurity(context);

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevelOverride.METHOD_LEVEL_SYSTEM_ACCOUNT1);

            assertThat(systemAccount).isEqualTo(ACCOUNT1);

        } catch (OctopusUnauthorizedException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }


}

