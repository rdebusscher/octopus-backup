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
package be.c4j.ee.security.result;

import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.interceptor.TestInvocationContext;
import be.c4j.ee.security.result.testclasses.ResultCheckBoundary;
import be.c4j.ee.security.result.testclasses.TrueResultVoter;
import be.c4j.test.util.BeanManagerFake;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.interceptor.InvocationContext;
import java.lang.reflect.Method;

/**
 *
 */
public class CheckResultInterceptorTest {

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();
    }

    @After
    public void teardown() {
        beanManagerFake.deregistration();
    }

    protected void finishCDISetup() throws IllegalAccessException {

        beanManagerFake.endRegistration();
    }

    @Test
    public void interceptResult_NoViolation() throws Exception {
        beanManagerFake.registerBean(new TrueResultVoter(), TrueResultVoter.class);
        finishCDISetup();

        Object target = new ResultCheckBoundary();
        Method method = target.getClass().getMethod("returnTrue");
        InvocationContext context = new TestInvocationContext(target, method);

        CheckResultInterceptor interceptor = new CheckResultInterceptor();
        interceptor.interceptResult(context);
    }

    @Test(expected = OctopusUnauthorizedException.class)
    public void interceptResult_WithViolation() throws Exception {
        beanManagerFake.registerBean(new TrueResultVoter(), TrueResultVoter.class);
        finishCDISetup();

        Object target = new ResultCheckBoundary();
        Method method = target.getClass().getMethod("returnFalse");
        InvocationContext context = new TestInvocationContext(target, method);

        CheckResultInterceptor interceptor = new CheckResultInterceptor();
        interceptor.interceptResult(context);
    }

    @Test(expected = CheckResultUsageException.class)
    public void interceptResult_missingVoter() throws Exception {
        beanManagerFake.registerBean(new TrueResultVoter(), TrueResultVoter.class);
        finishCDISetup();

        Object target = new ResultCheckBoundary();
        Method method = target.getClass().getMethod("missingVoter");
        InvocationContext context = new TestInvocationContext(target, method);

        CheckResultInterceptor interceptor = new CheckResultInterceptor();
        interceptor.interceptResult(context);
    }

}