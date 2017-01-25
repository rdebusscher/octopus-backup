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
 */
package be.c4j.ee.security.interceptor;

import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.interceptor.testclasses.ClassLevelCustomPermission;
import be.c4j.ee.security.permission.GenericPermissionVoter;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.PermissionLookupFixture;
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

    public OctopusInterceptor_ClassLevelCustomPermissionTest(boolean authenticated, String permission, boolean customAccess, String shiroPermission, String systemAccount) {
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
                {AUTHENTICATED, null, NO_CUSTOM_ACCESS, null, ACCOUNT1},           //6
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

        PermissionLookupFixture.registerPermissionLookup(beanManagerFake);

        finishCDISetup();

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

