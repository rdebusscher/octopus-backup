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

import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.config.VoterNameFactory;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import be.c4j.ee.security.exception.violation.BasicAuthorizationViolation;
import be.c4j.ee.security.interceptor.checks.AnnotationCheckFactory;
import be.c4j.ee.security.interceptor.checks.SecurityCheck;
import be.c4j.ee.security.interceptor.checks.SecurityCheckCustomCheck;
import be.c4j.ee.security.interceptor.testclasses.MethodLevel;
import be.c4j.ee.security.interceptor.testclasses.MyCheck;
import be.c4j.ee.security.octopus.AnnotationAuthorizationChecker;
import be.c4j.ee.security.permission.GenericPermissionVoter;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.test.util.BeanManagerFake;
import be.c4j.test.util.ReflectionUtil;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import javax.interceptor.InvocationContext;
import java.lang.reflect.Method;
import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class OctopusInterceptor_CustomCheck {

    private BeanManagerFake beanManagerFake;

    @Mock
    private OctopusConfig octopusConfigMock;

    @Mock
    private SecurityViolationInfoProducer infoProducerMock;

    @Mock
    private Subject subjectMock;

    @Mock
    private GenericPermissionVoter genericPermissionVoterMock;

    @InjectMocks
    protected OctopusInterceptor octopusInterceptor;

    private VoterNameFactory voterNameFactory;

    @Captor
    private ArgumentCaptor<AccessDecisionVoterContext> accessDecisionVoterCaptor;

    @Before
    public void setup() throws IllegalAccessException {
        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean(octopusConfigMock, OctopusConfig.class);

        // SecurityViolationInfoProducer mock instance assigned to CDI and playback
        beanManagerFake.registerBean(infoProducerMock, SecurityViolationInfoProducer.class);
        when(infoProducerMock.getViolationInfo(any(AccessDecisionVoterContext.class), any(NamedDomainPermission.class))).thenReturn("Violation Info");
        when(infoProducerMock.getViolationInfo(any(AccessDecisionVoterContext.class))).thenReturn("Violation Info");
        when(infoProducerMock.defineOctopusViolation(any(InvocationContext.class), any(Permission.class))).thenReturn(new BasicAuthorizationViolation("X", "Y"));

        voterNameFactory = new VoterNameFactory();
        ReflectionUtil.injectDependencies(voterNameFactory, octopusConfigMock);
        when(octopusConfigMock.getCustomCheckSuffix()).thenReturn("AccessDecissionVoter");

        SecurityCheckCustomCheck securityCheckCustomCheck = new SecurityCheckCustomCheck();
        ReflectionUtil.injectDependencies(securityCheckCustomCheck, infoProducerMock, octopusConfigMock, voterNameFactory);

        beanManagerFake.registerBean(securityCheckCustomCheck, SecurityCheck.class);

        beanManagerFake.registerBean("myCheckAccessDecissionVoter", genericPermissionVoterMock);


        // Define the Custom check class
        when(octopusConfigMock.getCustomCheckClass()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                return MyCheck.class;
            }
        });

        ThreadContext.bind(subjectMock);

    }

    @After
    public void teardown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void testAuthenticated_validCheck() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("customBasic");
        InvocationContext context = new TestInvocationContext(target, method);

        finishSetup();

        // authenticated
        when(subjectMock.isAuthenticated()).thenReturn(Boolean.TRUE);

        when(genericPermissionVoterMock.checkPermission(any(AccessDecisionVoterContext.class))).thenReturn(new HashSet<SecurityViolation>());

        octopusInterceptor.interceptShiroSecurity(context);

        verify(genericPermissionVoterMock).checkPermission(accessDecisionVoterCaptor.capture());

        AccessDecisionVoterContext voterContext = accessDecisionVoterCaptor.getValue();
        InvocationContext invocationContext = voterContext.getSource();
        // Test to make sure the AnnotationInfo is passed into the contextData
        assertThat(invocationContext.getContextData()).hasSize(1);
        assertThat(invocationContext.getContextData()).containsOnlyKeys(AnnotationInfo.class.getName());

    }

    @Test(expected = OctopusUnauthorizedException.class)
    public void testAuthenticated_NotValidCheck() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("customBasic");
        InvocationContext context = new TestInvocationContext(target, method);

        finishSetup();

        // authenticated
        when(subjectMock.isAuthenticated()).thenReturn(Boolean.TRUE);

        HashSet<SecurityViolation> violations = new HashSet<SecurityViolation>();
        violations.add(new BasicAuthorizationViolation("JUnit", null));
        when(genericPermissionVoterMock.checkPermission(any(AccessDecisionVoterContext.class))).thenReturn(violations);

        try {
            octopusInterceptor.interceptShiroSecurity(context);
        } finally {

            verify(genericPermissionVoterMock).checkPermission(accessDecisionVoterCaptor.capture());
        }

    }

    @Test(expected = OctopusUnauthorizedException.class)
    public void testNotAuthenticated() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("customBasic");
        InvocationContext context = new TestInvocationContext(target, method);

        finishSetup();

        // NOT authenticated
        when(subjectMock.isAuthenticated()).thenReturn(Boolean.FALSE);

        HashSet<SecurityViolation> violations = new HashSet<SecurityViolation>();
        violations.add(new BasicAuthorizationViolation("JUnit", null));
        when(genericPermissionVoterMock.checkPermission(any(AccessDecisionVoterContext.class))).thenReturn(violations);

        try {
            octopusInterceptor.interceptShiroSecurity(context);
        } finally {

            verify(genericPermissionVoterMock, never()).checkPermission(accessDecisionVoterCaptor.capture());
        }

    }

    protected void finishSetup() throws IllegalAccessException {

        beanManagerFake.endRegistration();

        AnnotationAuthorizationChecker authorizationChecker = new AnnotationAuthorizationChecker();

        AnnotationCheckFactory checkFactory = new AnnotationCheckFactory();
        checkFactory.init();

        ReflectionUtil.injectDependencies(authorizationChecker, checkFactory);

        ReflectionUtil.injectDependencies(octopusInterceptor, authorizationChecker);
    }

}
