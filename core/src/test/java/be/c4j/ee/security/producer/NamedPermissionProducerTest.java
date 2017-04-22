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
import be.c4j.ee.security.permission.GenericPermissionVoter;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.PermissionLookup;
import be.c4j.ee.security.permission.StringPermissionLookup;
import be.c4j.ee.security.producer.testclasses.TestPermissionAnnotation;
import be.c4j.ee.security.producer.testclasses.TestPermissionAnnotationCheck;
import be.c4j.ee.security.realm.OctopusPermissions;
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
public class NamedPermissionProducerTest {

    public static final String TEST_PERMISSION = "testPermission";
    @Mock
    private InjectionPoint injectionPointMock;

    @Mock
    private Annotated annotatedMock;

    @Mock
    private TestPermissionAnnotationCheck testPermissionAnnotationCheckMock;

    @Mock
    private OctopusPermissions octopusPermissionsMock;

    @Mock
    private VoterNameFactory voterNameFactoryMock;

    @Mock
    private PermissionLookup permissionLookupMock;

    @Mock
    private StringPermissionLookup stringPermissionLookupMock;

    private OctopusConfig octopusConfigMock;

    private BeanManagerFake beanManagerFake;

    private GenericPermissionVoter correctPermissionVoter;

    @InjectMocks
    private NamedPermissionProducer producer;

    @Before
    public void setUp() {

        when(injectionPointMock.getAnnotated()).thenReturn(annotatedMock);

        beanManagerFake = new BeanManagerFake();
        correctPermissionVoter = new GenericPermissionVoter();
    }

    private void registerOctopusConfig(Class<? extends Annotation> namedPermissionCheckClass) throws IllegalAccessException {
        octopusConfigMock = new OctopusConfigMock(namedPermissionCheckClass);
        ReflectionUtil.injectDependencies(producer, octopusConfigMock);
    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void getVoter() throws IllegalAccessException {
        registerOctopusConfig(TestPermissionAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestPermissionAnnotationCheck.class)).thenReturn(testPermissionAnnotationCheckMock);

        when(testPermissionAnnotationCheckMock.value()).thenReturn(new TestPermissionAnnotation[]{TestPermissionAnnotation.TEST});
        when(voterNameFactoryMock.generatePermissionBeanName("TEST")).thenReturn("testVoter");
        beanManagerFake.registerBean("testVoter", correctPermissionVoter);
        beanManagerFake.endRegistration();

        GenericPermissionVoter voter = producer.getVoter(injectionPointMock);

        assertThat(voter).isEqualTo(correctPermissionVoter);
    }

    @Test(expected = UnsatisfiedResolutionException.class)
    public void getVoter_NoAnnotation() throws IllegalAccessException {
        registerOctopusConfig(TestPermissionAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestPermissionAnnotationCheck.class)).thenReturn(null);

        producer.getVoter(injectionPointMock);

    }

    @Test(expected = AmbiguousResolutionException.class)
    public void getVoter_MultipleValues() throws IllegalAccessException {
        registerOctopusConfig(TestPermissionAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestPermissionAnnotationCheck.class)).thenReturn(testPermissionAnnotationCheckMock);

        when(testPermissionAnnotationCheckMock.value()).thenReturn(new TestPermissionAnnotation[]{TestPermissionAnnotation.TEST, TestPermissionAnnotation.SECOND});

        producer.getVoter(injectionPointMock);
    }

    @Test
    public void getVoter_WithOctopusPermission() throws IllegalAccessException {
        registerOctopusConfig(TestPermissionAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestPermissionAnnotationCheck.class)).thenReturn(null);
        when(annotatedMock.getAnnotation(OctopusPermissions.class)).thenReturn(octopusPermissionsMock);

        when(octopusPermissionsMock.value()).thenReturn(new String[]{TEST_PERMISSION});

        when(stringPermissionLookupMock.getPermission(TEST_PERMISSION)).thenReturn(new NamedDomainPermission(TEST_PERMISSION, "test:*:*"));

        Subject subjectMock = mock(Subject.class);
        beanManagerFake.registerBean(subjectMock, Subject.class);

        beanManagerFake.endRegistration();

        GenericPermissionVoter voter = producer.getVoter(injectionPointMock);

        assertThat(voter).isNotEqualTo(correctPermissionVoter);  // Because we need to test that BeanManager isn't used.

        voter.verifyPermission();

        ArgumentCaptor<NamedDomainPermission> argument = ArgumentCaptor.forClass(NamedDomainPermission.class);
        verify(subjectMock).checkPermission(argument.capture());
        assertThat(argument.getValue().getName()).isEqualTo(TEST_PERMISSION);
    }

    @Test
    public void getVoter_WithOctopusPermission_version2() throws IllegalAccessException {
        registerOctopusConfig(null);
        when(annotatedMock.getAnnotation(OctopusPermissions.class)).thenReturn(octopusPermissionsMock);

        when(octopusPermissionsMock.value()).thenReturn(new String[]{TEST_PERMISSION});

        when(stringPermissionLookupMock.getPermission(TEST_PERMISSION)).thenReturn(new NamedDomainPermission(TEST_PERMISSION, "test:*:*"));

        Subject subjectMock = mock(Subject.class);
        beanManagerFake.registerBean(subjectMock, Subject.class);

        beanManagerFake.endRegistration();

        GenericPermissionVoter voter = producer.getVoter(injectionPointMock);

        assertThat(voter).isNotEqualTo(correctPermissionVoter);  // Because we need to test that BeanManager isn't used.

        voter.verifyPermission();

        ArgumentCaptor<NamedDomainPermission> argument = ArgumentCaptor.forClass(NamedDomainPermission.class);
        verify(subjectMock).checkPermission(argument.capture());
        assertThat(argument.getValue().getName()).isEqualTo(TEST_PERMISSION);
    }

    @Test(expected = UnsatisfiedResolutionException.class)
    public void getVoter_NoInfoAtAll() throws IllegalAccessException {
        registerOctopusConfig(null);
        when(annotatedMock.getAnnotation(OctopusPermissions.class)).thenReturn(null);

        producer.getVoter(injectionPointMock);

    }

    @Test(expected = AmbiguousResolutionException.class)
    public void getVoter_WithOctopusPermission_MultipleValues() throws IllegalAccessException {
        registerOctopusConfig(null);
        when(annotatedMock.getAnnotation(OctopusPermissions.class)).thenReturn(octopusPermissionsMock);

        when(octopusPermissionsMock.value()).thenReturn(new String[]{TEST_PERMISSION, "SecondPermission"});

        producer.getVoter(injectionPointMock);
    }

    @Test
    public void getPermission() throws IllegalAccessException {
        registerOctopusConfig(TestPermissionAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestPermissionAnnotationCheck.class)).thenReturn(testPermissionAnnotationCheckMock);

        when(testPermissionAnnotationCheckMock.value()).thenReturn(new TestPermissionAnnotation[]{TestPermissionAnnotation.TEST});

        NamedDomainPermission namedDomainPermission = new NamedDomainPermission("test", "test:junit:*");
        when(permissionLookupMock.getPermission(TestPermissionAnnotation.TEST.name())).thenReturn(namedDomainPermission);

        NamedDomainPermission permission = producer.getPermission(injectionPointMock);
        assertThat(permission).isEqualTo(namedDomainPermission);
    }

    @Test(expected = UnsatisfiedResolutionException.class)
    public void getPermission_NoAnnotation() throws IllegalAccessException {
        registerOctopusConfig(TestPermissionAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestPermissionAnnotationCheck.class)).thenReturn(null);

        producer.getPermission(injectionPointMock);

    }

    @Test(expected = AmbiguousResolutionException.class)
    public void getPermission_MultipleValues() throws IllegalAccessException {
        registerOctopusConfig(TestPermissionAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestPermissionAnnotationCheck.class)).thenReturn(testPermissionAnnotationCheckMock);

        when(testPermissionAnnotationCheckMock.value()).thenReturn(new TestPermissionAnnotation[]{TestPermissionAnnotation.TEST, TestPermissionAnnotation.SECOND});

        producer.getPermission(injectionPointMock);
    }

    @Test
    public void getPermission_withOctopusPermission() throws IllegalAccessException {
        registerOctopusConfig(TestPermissionAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestPermissionAnnotationCheck.class)).thenReturn(null);
        when(annotatedMock.getAnnotation(OctopusPermissions.class)).thenReturn(octopusPermissionsMock);

        when(octopusPermissionsMock.value()).thenReturn(new String[]{TEST_PERMISSION});

        when(stringPermissionLookupMock.getPermission(TEST_PERMISSION)).thenReturn(new NamedDomainPermission(TEST_PERMISSION, "test:*:*"));

        NamedDomainPermission permission = producer.getPermission(injectionPointMock);
        assertThat(permission.getWildcardNotation()).isEqualTo("test:*:*");
    }

    @Test(expected = UnsatisfiedResolutionException.class)
    public void getPermission_NoInfoAtAll() throws IllegalAccessException {
        registerOctopusConfig(null);
        when(annotatedMock.getAnnotation(OctopusPermissions.class)).thenReturn(null);

        producer.getPermission(injectionPointMock);

    }

    @Test(expected = AmbiguousResolutionException.class)
    public void getPermission_WithOctopusPermission_MultipleValues() throws IllegalAccessException {
        registerOctopusConfig(null);
        when(annotatedMock.getAnnotation(OctopusPermissions.class)).thenReturn(octopusPermissionsMock);

        when(octopusPermissionsMock.value()).thenReturn(new String[]{TEST_PERMISSION, "SecondPermission"});

        producer.getPermission(injectionPointMock);
    }

    private static class OctopusConfigMock extends OctopusConfig {

        private Class<? extends Annotation> namedPermissionCheckClass;

        public OctopusConfigMock(Class<? extends Annotation> namedPermissionCheckClass) {
            this.namedPermissionCheckClass = namedPermissionCheckClass;
        }

        @Override
        public Class<? extends Annotation> getNamedPermissionCheckClass() {
            return namedPermissionCheckClass;

        }
    }


}