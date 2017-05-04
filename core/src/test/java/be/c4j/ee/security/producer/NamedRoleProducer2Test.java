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
package be.c4j.ee.security.producer;

import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.realm.OctopusRoles;
import be.c4j.ee.security.role.GenericRoleVoter;
import be.c4j.ee.security.role.NamedApplicationRole;
import be.c4j.ee.security.role.RoleLookup;
import be.c4j.test.util.BeanManagerFake;
import be.c4j.test.util.ReflectionUtil;
import org.apache.shiro.subject.Subject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import javax.enterprise.inject.AmbiguousResolutionException;
import javax.enterprise.inject.UnsatisfiedResolutionException;
import javax.enterprise.inject.spi.Annotated;
import javax.enterprise.inject.spi.InjectionPoint;
import java.lang.annotation.Annotation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class NamedRoleProducer2Test {

    private static final String TEST_ROLE = "testROLE";

    @Mock
    private InjectionPoint injectionPointMock;

    @Mock
    private Annotated annotatedMock;

    @Mock
    private OctopusRoles octopusRolesMock;

    private OctopusConfig octopusConfigMock;

    private BeanManagerFake beanManagerFake;

    private GenericRoleVoter correctRoleVoter;

    @InjectMocks
    private NamedRoleProducer producer;

    @Before
    public void setUp() throws IllegalAccessException {

        when(injectionPointMock.getAnnotated()).thenReturn(annotatedMock);

        beanManagerFake = new BeanManagerFake();
        correctRoleVoter = new GenericRoleVoter();

        octopusConfigMock = new NamedRoleProducer2Test.OctopusConfigMock();
        ReflectionUtil.injectDependencies(producer, octopusConfigMock);
    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test(expected = UnsatisfiedResolutionException.class)
    public void testGetVoter_missingAnnotation() throws IllegalAccessException {

        beanManagerFake.endRegistration();

        producer.getVoter(injectionPointMock);

    }

    @Test
    public void testGetVoter_WithNamedRole() throws IllegalAccessException {
        RoleLookup roleLookupMock = Mockito.mock(RoleLookup.class);
        beanManagerFake.registerBean(roleLookupMock, RoleLookup.class);
        NamedApplicationRole namedRole = new NamedApplicationRole("testRoleLookup");
        when(roleLookupMock.getRole(TEST_ROLE)).thenReturn(namedRole);

        when(annotatedMock.getAnnotation(OctopusRoles.class)).thenReturn(octopusRolesMock);

        when(octopusRolesMock.value()).thenReturn(new String[]{TEST_ROLE});

        Subject subjectMock = mock(Subject.class);
        beanManagerFake.registerBean(subjectMock, Subject.class);

        beanManagerFake.endRegistration();
        producer.init();

        GenericRoleVoter voter = producer.getVoter(injectionPointMock);

        assertThat(voter).isNotEqualTo(correctRoleVoter);  // Because we need to test that BeanManager isn't used.

        voter.verifyPermission();

        ArgumentCaptor<NamedApplicationRole> argument = ArgumentCaptor.forClass(NamedApplicationRole.class);
        verify(subjectMock).checkPermission(argument.capture());
        assertThat(argument.getValue().getRoleName()).isEqualTo("testRoleLookup");
    }

    @Test
    public void testGetVoter_WithStringRole() throws IllegalAccessException {
        when(annotatedMock.getAnnotation(OctopusRoles.class)).thenReturn(octopusRolesMock);

        when(octopusRolesMock.value()).thenReturn(new String[]{TEST_ROLE});

        Subject subjectMock = mock(Subject.class);
        beanManagerFake.registerBean(subjectMock, Subject.class);

        beanManagerFake.endRegistration();

        GenericRoleVoter voter = producer.getVoter(injectionPointMock);

        assertThat(voter).isNotEqualTo(correctRoleVoter);  // Because we need to test that BeanManager isn't used.

        voter.verifyPermission();

        ArgumentCaptor<NamedApplicationRole> argument = ArgumentCaptor.forClass(NamedApplicationRole.class);
        verify(subjectMock).checkPermission(argument.capture());
        assertThat(argument.getValue().getRoleName()).isEqualTo(TEST_ROLE);
    }

    @Test
    public void getRole() throws IllegalAccessException {
        when(annotatedMock.getAnnotation(OctopusRoles.class)).thenReturn(octopusRolesMock);

        when(octopusRolesMock.value()).thenReturn(new String[]{TEST_ROLE});

        beanManagerFake.endRegistration();

        NamedApplicationRole role = producer.getRole(injectionPointMock);

        assertThat(role.getRoleName()).isEqualTo(TEST_ROLE);
    }


    @Test(expected = AmbiguousResolutionException.class)
    public void getRole_multiple_Named() throws IllegalAccessException {
        when(annotatedMock.getAnnotation(OctopusRoles.class)).thenReturn(octopusRolesMock);

        when(octopusRolesMock.value()).thenReturn(new String[]{"a", "b"});

        beanManagerFake.endRegistration();

        producer.getRole(injectionPointMock);
    }

    @Test(expected = UnsatisfiedResolutionException.class)
    public void getRole_missingAnnotation_named() throws IllegalAccessException {
        when(annotatedMock.getAnnotation(OctopusRoles.class)).thenReturn(null);

        beanManagerFake.endRegistration();

        producer.getRole(injectionPointMock);
    }

    private static class OctopusConfigMock extends OctopusConfig {

        @Override
        public Class<? extends Annotation> getNamedRoleCheckClass() {
            return null;
        }
    }


}