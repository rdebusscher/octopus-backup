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
import be.c4j.ee.security.config.VoterNameFactory;
import be.c4j.ee.security.producer.testclasses.TestRoleAnnotation;
import be.c4j.ee.security.producer.testclasses.TestRoleAnnotationCheck;
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
public class NamedRoleProducerTest {

    public static final String TEST_ROLE = "testROLE";

    @Mock
    private InjectionPoint injectionPointMock;

    @Mock
    private Annotated annotatedMock;

    @Mock
    private TestRoleAnnotationCheck testRoleAnnotationCheckMock;

    @Mock
    private OctopusRoles octopusRolesMock;

    @Mock
    private VoterNameFactory voterNameFactoryMock;

    // FIXME Another test class with no RoleLookup.
    @Mock
    private RoleLookup roleLookupMock;

    private OctopusConfig octopusConfigMock;

    private BeanManagerFake beanManagerFake;

    private GenericRoleVoter correctRoleVoter;

    @InjectMocks
    private NamedRoleProducer producer;

    @Before
    public void setUp() {

        when(injectionPointMock.getAnnotated()).thenReturn(annotatedMock);

        beanManagerFake = new BeanManagerFake();
        correctRoleVoter = new GenericRoleVoter();
    }

    private void registerOctopusConfig(Class<? extends Annotation> namedRoleCheckClass) throws IllegalAccessException {
        octopusConfigMock = new NamedRoleProducerTest.OctopusConfigMock(namedRoleCheckClass);
        ReflectionUtil.injectDependencies(producer, octopusConfigMock);
    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void testGetVoter() throws IllegalAccessException {
        registerOctopusConfig(TestRoleAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestRoleAnnotationCheck.class)).thenReturn(testRoleAnnotationCheckMock);

        when(testRoleAnnotationCheckMock.value()).thenReturn(new TestRoleAnnotation[]{TestRoleAnnotation.TEST});
        when(voterNameFactoryMock.generateRoleBeanName("TEST")).thenReturn("testVoter");
        beanManagerFake.registerBean("testVoter", correctRoleVoter);
        beanManagerFake.endRegistration();

        GenericRoleVoter voter = producer.getVoter(injectionPointMock);

        assertThat(voter).isEqualTo(correctRoleVoter);
    }

    @Test(expected = UnsatisfiedResolutionException.class)
    public void testGetVoter_NoAnnotation() throws IllegalAccessException {
        registerOctopusConfig(TestRoleAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestRoleAnnotationCheck.class)).thenReturn(null);

        producer.getVoter(injectionPointMock);

    }

    @Test(expected = AmbiguousResolutionException.class)
    public void testGetVoter_MultipleValues() throws IllegalAccessException {
        registerOctopusConfig(TestRoleAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestRoleAnnotationCheck.class)).thenReturn(testRoleAnnotationCheckMock);

        when(testRoleAnnotationCheckMock.value()).thenReturn(new TestRoleAnnotation[]{TestRoleAnnotation.TEST, TestRoleAnnotation.SECOND});

        producer.getVoter(injectionPointMock);
    }

    @Test
    public void testGetVoter_WithNamedRole() throws IllegalAccessException {
        registerOctopusConfig(TestRoleAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestRoleAnnotationCheck.class)).thenReturn(null);
        when(annotatedMock.getAnnotation(OctopusRoles.class)).thenReturn(octopusRolesMock);

        when(octopusRolesMock.value()).thenReturn(new String[]{TEST_ROLE});

        when(roleLookupMock.getRole(TEST_ROLE)).thenReturn(new NamedApplicationRole(TEST_ROLE));

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
    public void testGetVoter_WithStringRole() throws IllegalAccessException {
        registerOctopusConfig(TestRoleAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestRoleAnnotationCheck.class)).thenReturn(null);
        when(annotatedMock.getAnnotation(OctopusRoles.class)).thenReturn(octopusRolesMock);

        when(octopusRolesMock.value()).thenReturn(new String[]{TEST_ROLE});

        when(roleLookupMock.getRole(TEST_ROLE)).thenReturn(null);

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

    @Test(expected = UnsatisfiedResolutionException.class)
    public void testGetVoter_NoInfoAtAll() throws IllegalAccessException {
        registerOctopusConfig(null);
        when(annotatedMock.getAnnotation(OctopusRoles.class)).thenReturn(null);

        producer.getVoter(injectionPointMock);

    }

    @Test(expected = AmbiguousResolutionException.class)
    public void testGetVoter_WithRoles_MultipleValues() throws IllegalAccessException {
        registerOctopusConfig(null);
        when(annotatedMock.getAnnotation(OctopusRoles.class)).thenReturn(octopusRolesMock);

        when(octopusRolesMock.value()).thenReturn(new String[]{TEST_ROLE, "SecondPermission"});

        producer.getVoter(injectionPointMock);
    }

    private static class OctopusConfigMock extends OctopusConfig {

        private Class<? extends Annotation> namedRoleCheckClass;

        public OctopusConfigMock(Class<? extends Annotation> namedRoleCheckClass) {
            this.namedRoleCheckClass = namedRoleCheckClass;
        }

        @Override
        public Class<? extends Annotation> getNamedRoleCheckClass() {
            return namedRoleCheckClass;

        }
    }


}