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
package be.c4j.ee.security.jwt.filter;

import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import be.c4j.ee.security.jwt.filter.testclasses.RestController;
import be.c4j.ee.security.octopus.AnnotationAuthorizationChecker;
import be.c4j.ee.security.util.AnnotationsToFind;
import be.c4j.test.util.BeanManagerFake;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import javax.ws.rs.container.ResourceInfo;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class OctopusAnnotationContainerRequestFilterTest {

    @Mock
    private ResourceInfo resourceInfoMock;

    @Mock
    private OctopusConfig configMock;

    @Mock
    private AnnotationAuthorizationChecker annotationAuthorizationCheckerMock;

    @Mock
    private SecurityViolationInfoProducer infoProducerMock;

    @InjectMocks
    private OctopusAnnotationContainerRequestFilter filter;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();
    }

    @After
    public void teardown() {
        beanManagerFake.deregistration();
    }

    @Test(expected = OctopusUnauthorizedException.class)
    public void filter_NoAnnotation() throws IOException, NoSuchMethodException {
        registerAdditionalAnnotation();

        when(resourceInfoMock.getResourceClass()).then(new Answer<Class<?>>() {
            @Override
            public Class<?> answer(InvocationOnMock invocation) throws Throwable {
                return RestController.class;
            }
        });
        Object target = new RestController();
        Method method = target.getClass().getMethod("noAnnotation");

        when(resourceInfoMock.getResourceMethod()).thenReturn(method);
        filter.filter(null);

        verify(annotationAuthorizationCheckerMock, times(2)).checkAccess(ArgumentMatchers.<Annotation>anySet(), any(AccessDecisionVoterContext.class));
    }

    @Test
    public void filter_ignoreAnnotation() throws IOException, NoSuchMethodException {
        registerAdditionalAnnotation();

        when(resourceInfoMock.getResourceClass()).then(new Answer<Class<?>>() {
            @Override
            public Class<?> answer(InvocationOnMock invocation) throws Throwable {
                return RestController.class;
            }
        });
        Object target = new RestController();
        Method method = target.getClass().getMethod("ignoreAnnotation");

        when(resourceInfoMock.getResourceMethod()).thenReturn(method);
        filter.filter(null);
    }

    @Test
    public void filter_requiresUser_valid() throws IOException, NoSuchMethodException {
        registerAdditionalAnnotation();

        when(resourceInfoMock.getResourceClass()).then(new Answer<Class<?>>() {
            @Override
            public Class<?> answer(InvocationOnMock invocation) throws Throwable {
                return RestController.class;
            }
        });
        Object target = new RestController();
        Method method = target.getClass().getMethod("requiresUser");

        when(resourceInfoMock.getResourceMethod()).thenReturn(method);

        when(annotationAuthorizationCheckerMock.checkAccess(ArgumentMatchers.<Annotation>anySet(), any(AccessDecisionVoterContext.class)))
                .thenReturn(true);

        filter.filter(null);
    }

    @Test(expected = OctopusUnauthorizedException.class)
    public void filter_requiresUser_invalid() throws IOException, NoSuchMethodException {
        registerAdditionalAnnotation();

        when(resourceInfoMock.getResourceClass()).then(new Answer<Class<?>>() {
            @Override
            public Class<?> answer(InvocationOnMock invocation) throws Throwable {
                return RestController.class;
            }
        });
        Object target = new RestController();
        Method method = target.getClass().getMethod("requiresUser");

        when(resourceInfoMock.getResourceMethod()).thenReturn(method);

        when(annotationAuthorizationCheckerMock.checkAccess(ArgumentMatchers.<Annotation>anySet(), any(AccessDecisionVoterContext.class)))
                .thenThrow(new OctopusUnauthorizedException("Mockito induced", "exceptionPoint"));

        filter.filter(null);

        verify(annotationAuthorizationCheckerMock).checkAccess(ArgumentMatchers.<Annotation>anySet(), any(AccessDecisionVoterContext.class));
    }

    private void registerAdditionalAnnotation() {
        AnnotationsToFind mock = Mockito.mock(AnnotationsToFind.class);
        beanManagerFake.registerBean(mock, AnnotationsToFind.class);
        beanManagerFake.endRegistration();

        List<Class<? extends Annotation>> extraAnnotations = new ArrayList<Class<? extends Annotation>>();
        extraAnnotations.add(IgnoreOctopusSCSRestFilter.class);
        when(mock.getList()).thenReturn(extraAnnotations);

    }

}