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
package be.c4j.ee.security.util;

import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.custom.CustomVoterCheck;
import be.c4j.ee.security.interceptor.AnnotationInfo;
import be.c4j.ee.security.interceptor.testclasses.*;
import be.c4j.ee.security.realm.OctopusPermissions;
import be.c4j.ee.security.realm.OnlyDuringAuthentication;
import be.c4j.ee.security.realm.OnlyDuringAuthorization;
import be.c4j.ee.security.systemaccount.SystemAccount;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import javax.annotation.security.PermitAll;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class AnnotationUtilTest {

    @Mock
    private OctopusConfig octopusConfigMock;

    @Before
    public void setup() {
        // Define the Named permission check class
        when(octopusConfigMock.getNamedPermissionCheckClass()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                return TestPermissionCheck.class;
            }
        });

    }

    @Test
    public void getAllAnnotations_ClassLevelCustomPermission() throws NoSuchMethodException {
        Object target = new ClassLevelCustomPermission();
        Method method = target.getClass().getMethod("customPermission1");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, ClassLevelCustomPermission.class, method);
        assertThat(annotations.getMethodAnnotations()).isEmpty();
        assertThat(annotations.getClassAnnotations()).hasSize(1);

        Annotation annotation = annotations.getClassAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(TestPermissionCheck.class);

        assertThat(((TestPermissionCheck) annotation).value()).containsOnly(TestPermission.PERMISSION1);
    }

    @Test
    public void getAllAnnotations_ClassLevelCustomVoter() throws NoSuchMethodException {

        Object target = new ClassLevelCustomVoter();
        Method method = target.getClass().getMethod("customVoter1");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, ClassLevelCustomVoter.class, method);
        assertThat(annotations.getMethodAnnotations()).isEmpty();
        assertThat(annotations.getClassAnnotations()).hasSize(1);

        Annotation annotation = annotations.getClassAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(CustomVoterCheck.class);

        assertThat(((CustomVoterCheck) annotation).value()).containsOnly(TestCustomVoter.class);
    }

    @Test
    public void getAllAnnotations_ClassLevelPermitAll() throws NoSuchMethodException {

        Object target = new ClassLevelPermitAll();
        Method method = target.getClass().getMethod("permitAll1");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, ClassLevelPermitAll.class, method);
        assertThat(annotations.getMethodAnnotations()).isEmpty();
        assertThat(annotations.getClassAnnotations()).hasSize(1);

        Annotation annotation = annotations.getClassAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(PermitAll.class);

    }

    @Test
    public void getAllAnnotations_ClassLevelRequiresPermissions() throws NoSuchMethodException {

        Object target = new ClassLevelRequiresPermissions();
        Method method = target.getClass().getMethod("requiresPermissions1");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, ClassLevelRequiresPermissions.class, method);
        assertThat(annotations.getMethodAnnotations()).isEmpty();
        assertThat(annotations.getClassAnnotations()).hasSize(1);

        Annotation annotation = annotations.getClassAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(RequiresPermissions.class);

        assertThat(((RequiresPermissions) annotation).value()).containsOnly("shiro1:*:*");

    }

    @Test
    public void getAllAnnotations_ClassLevelRequiresUser() throws NoSuchMethodException {

        Object target = new ClassLevelRequiresUser();
        Method method = target.getClass().getMethod("requiresUser1");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, ClassLevelRequiresUser.class, method);
        assertThat(annotations.getMethodAnnotations()).isEmpty();
        assertThat(annotations.getClassAnnotations()).hasSize(1);

        Annotation annotation = annotations.getClassAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(RequiresUser.class);
    }

    @Test
    public void getAllAnnotations_ClassLevelSystemAccount() throws NoSuchMethodException {

        Object target = new ClassLevelSystemAccount();
        Method method = target.getClass().getMethod("systemAccount1");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, ClassLevelSystemAccount.class, method);
        assertThat(annotations.getMethodAnnotations()).isEmpty();
        assertThat(annotations.getClassAnnotations()).hasSize(1);

        Annotation annotation = annotations.getClassAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(SystemAccount.class);

        assertThat(((SystemAccount) annotation).value()).containsOnly("account1");

    }

    @Test
    public void getAllAnnotations_MethodLevelPermitAll() throws NoSuchMethodException {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("permitAll");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(PermitAll.class);

    }

    @Test
    public void getAllAnnotations_MethodLevelNoAnnotation() throws NoSuchMethodException {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("noAnnotation");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).isEmpty();

    }

    @Test
    public void getAllAnnotations_MethodLevelRequiresUser() throws NoSuchMethodException {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("requiresUser");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(RequiresUser.class);

    }

    @Test
    public void getAllAnnotations_MethodLevelOnlyDuringAuthentication() throws NoSuchMethodException {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("inAuthentication");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(OnlyDuringAuthentication.class);

    }

    @Test
    public void getAllAnnotations_MethodLevelOnlyDuringAuthorization() throws NoSuchMethodException {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("inAuthorization");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(OnlyDuringAuthorization.class);

    }

    @Test
    public void getAllAnnotations_MethodLevelTestPermissionCheck() throws NoSuchMethodException {
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("permission2");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(TestPermissionCheck.class);

        assertThat(((TestPermissionCheck) annotation).value()).containsOnly(TestPermission.PERMISSION2);
    }

    @Test
    public void getAllAnnotations_MethodLevelCustomVoterCheck() throws NoSuchMethodException {
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("customVoter");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(CustomVoterCheck.class);

        assertThat(((CustomVoterCheck) annotation).value()).containsOnly(TestCustomVoter.class);
    }

    @Test
    public void getAllAnnotations_MethodLevelRequiresPermissions() throws NoSuchMethodException {
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("requiresPermission2");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(RequiresPermissions.class);

        assertThat(((RequiresPermissions) annotation).value()).containsOnly("shiro2:*:*");
    }

    @Test
    public void getAllAnnotations_MethodLevelSystemAccount() throws NoSuchMethodException {
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("systemAccountValue2");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(SystemAccount.class);

        assertThat(((SystemAccount) annotation).value()).containsOnly("account2");
    }

    @Test
    public void getAllAnnotations_MethodLevelOctopusPermissions_1() throws NoSuchMethodException {
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("octopusPermission1");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(OctopusPermissions.class);

        assertThat(((OctopusPermissions) annotation).value()).containsOnly("permissionName");
    }

    @Test
    public void getAllAnnotations_MethodLevelOctopusPermissions_2() throws NoSuchMethodException {
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("octopusPermission2");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(OctopusPermissions.class);

        assertThat(((OctopusPermissions) annotation).value()).containsOnly("octopus:action:*");
    }

    @Test
    public void getAllAnnotations_MultipleAtMethodLevel() throws NoSuchMethodException {
        Object target = new MultipleAtMethodLevel();
        Method method = target.getClass().getMethod("multiple");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MultipleAtMethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(2);

        // I assume that the correct ones are retrieved
    }
}