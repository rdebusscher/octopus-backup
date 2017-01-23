/*
 * Copyright 2014-2017 Rudy De Busscher (www.c4j.be)
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
import be.c4j.ee.security.interceptor.testclasses.MultipleAtMethodLevel;
import be.c4j.ee.security.permission.GenericPermissionVoter;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.PermissionLookupFixture;
import be.c4j.ee.security.realm.OctopusRealm;
import be.c4j.ee.security.twostep.TwoStepConfig;
import be.c4j.util.ReflectionUtil;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.Mockito;

import javax.interceptor.InvocationContext;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(Parameterized.class)
public class OctopusInterceptor_MultipleAtMethodLevelTest extends OctopusInterceptorTest {

    public OctopusInterceptor_MultipleAtMethodLevelTest(boolean authenticated, String permission, boolean customAccess, String shiroPermission, String systemAccount) {
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
    public void testInterceptShiroSecurity_InAuthentication() throws Exception {

        Object target = new MultipleAtMethodLevel();
        Method method = target.getClass().getMethod("multiple");
        InvocationContext context = new TestInvocationContext(target, method);

        // The in Authentication is so encapsulated that we can never set it outside the class (as we could manipulate then the security)
        // That is also the reason we have to simulate a larger part to test this.

        OctopusRealm octopusRealm = new OctopusRealm();
        OctopusConfig octopusConfigMock = Mockito.mock(OctopusConfig.class);
        when(octopusConfigMock.getHashAlgorithmName()).thenReturn("");

        TwoStepConfig twoStepConfigMock = Mockito.mock(TwoStepConfig.class);
        when(twoStepConfigMock.getAlwaysTwoStepAuthentication()).thenReturn(false);

        ReflectionUtil.injectDependencies(octopusRealm, new TestSecurityDataProvider(context), octopusConfigMock, twoStepConfigMock);
        registerPermissionVoter();

        finishCDISetup();

        try {
            octopusRealm.getAuthenticationInfo(null);

            if (PERMISSION1.equals(permission)) {
                assertThat(authenticated).isTrue();
            }
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MultipleAtMethodLevel.MULTIPLE_CHECKS);

        } catch (OctopusUnauthorizedException e) {
            assertThat(authenticated).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }


    @Test
    public void testInterceptShiroSecurity_CustomPermissionAnnotation() throws Exception {

        Object target = new MultipleAtMethodLevel();
        Method method = target.getClass().getMethod("multiple");
        InvocationContext context = new TestInvocationContext(target, method);

        registerPermissionVoter();

        PermissionLookupFixture.registerPermissionLookup(beanManagerFake);

        finishCDISetup();

        try {
            octopusInterceptor.interceptShiroSecurity(context);

            assertThat(permission).isEqualTo(PERMISSION1);
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MultipleAtMethodLevel.MULTIPLE_CHECKS);

        } catch (OctopusUnauthorizedException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();

        }
    }

    private void registerPermissionVoter() throws IllegalAccessException {
        GenericPermissionVoter permissionVoter = new GenericPermissionVoter();
        NamedDomainPermission namedPermission = getNamedDomainPermission(PERMISSION1);
        ReflectionUtil.injectDependencies(permissionVoter, subjectMock, namedPermission);

        beanManagerFake.registerBean("permission1PermissionVoter", permissionVoter);
    }

}

