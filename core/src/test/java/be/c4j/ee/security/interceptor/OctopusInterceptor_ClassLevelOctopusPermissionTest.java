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
import be.c4j.ee.security.interceptor.testclasses.ClassLevelOctopusPermission;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.StringPermissionLookupFixture;
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
public class OctopusInterceptor_ClassLevelOctopusPermissionTest extends OctopusInterceptorTest {

    public OctopusInterceptor_ClassLevelOctopusPermissionTest(boolean authenticated, String permission, boolean customAccess, String shiroPermission, String systemAccount) {
        super(authenticated, permission, customAccess, shiroPermission, systemAccount);
    }

    @Parameterized.Parameters
    public static List<Object[]> defineScenarios() {
        return Arrays.asList(new Object[][]{
                {NOT_AUTHENTICATED, null, NO_CUSTOM_ACCESS, null, null},            //0
                {NOT_AUTHENTICATED, null, CUSTOM_ACCESS, null, null},               //1
                {AUTHENTICATED, null, NO_CUSTOM_ACCESS, null, null},                //2
                {AUTHENTICATED, PERMISSION1, NO_CUSTOM_ACCESS, null, null},        //3
                {AUTHENTICATED, PERMISSION2, NO_CUSTOM_ACCESS, null, null},        //4
                {AUTHENTICATED, null, CUSTOM_ACCESS, null, null},                   //5
                {AUTHENTICATED, null, NO_CUSTOM_ACCESS, SHIRO1, null},            //6
                {AUTHENTICATED, null, NO_CUSTOM_ACCESS, null, ACCOUNT1},           //7
        });
    }

    @Test
    public void testInterceptShiroSecurity_octopusPermission1() throws Exception {

        Object target = new ClassLevelOctopusPermission();
        Method method = target.getClass().getMethod("octopusPermission1");
        InvocationContext context = new TestInvocationContext(target, method);

        performAndCheck(context);
    }

    private void performAndCheck(InvocationContext context) throws Exception {

        StringPermissionLookupFixture.registerLookup(beanManagerFake);

        finishCDISetup();

        securityCheckOctopusPermission.init();

        try {
            octopusInterceptor.interceptShiroSecurity(context);

            assertThat(permission).isEqualTo(PERMISSION1);
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(ClassLevelOctopusPermission.CLASS_LEVEL_OCTOPUS_PERMISSION);

        } catch (OctopusUnauthorizedException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();

            assertThat(permission).isNotEqualToIgnoringCase(PERMISSION1);
        }
    }

    @Test
    public void testInterceptShiroSecurity_octopusPermission1Bis() throws Exception {

        Object target = new ClassLevelOctopusPermission();
        Method method = target.getClass().getMethod("octopusPermission1Bis");
        InvocationContext context = new TestInvocationContext(target, method);

        performAndCheck(context);
    }

    protected NamedDomainPermission getNamedDomainPermission(String permissionName) {
        NamedDomainPermission result = null;
        if ("permission1".equalsIgnoreCase(permissionName)) {

            result = new NamedDomainPermission(permissionName, "SPermission", "1", "*");
        }
        if ("permission2".equalsIgnoreCase(permissionName)) {

            result = new NamedDomainPermission(permissionName, "SPermission", "2", "*");
        }
        if ("permission3".equalsIgnoreCase(permissionName)) {

            result = new NamedDomainPermission(permissionName, "SPermission", "3", "*");
        }
        return result;
    }

}

