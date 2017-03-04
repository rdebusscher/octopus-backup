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

import be.c4j.ee.security.CustomAccessDecissionVoterContext;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.context.OctopusSecurityContext;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import be.c4j.ee.security.octopus.AnnotationAuthorizationChecker;
import be.c4j.ee.security.util.AnnotationUtil;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;

import javax.ejb.Asynchronous;
import javax.inject.Inject;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;
import java.io.Serializable;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Set;

@Interceptor
@OctopusInterceptorBinding
public class OctopusInterceptor implements Serializable {

    private static final long serialVersionUID = 1L;

    @Inject
    private OctopusConfig config;

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    @Inject
    private AnnotationAuthorizationChecker annotationAuthorizationChecker;

    //@PostConstruct With Weld 2.X, there seems to be an issue
    public void init(InvocationContext context) {
        if (config == null) {
            // WLS12C doesn't inject into interceptors
            config = BeanProvider.getContextualReference(OctopusConfig.class);
            infoProducer = BeanProvider.getContextualReference(SecurityViolationInfoProducer.class);
            annotationAuthorizationChecker = BeanProvider.getContextualReference(AnnotationAuthorizationChecker.class);
        }
    }

    @AroundInvoke
    public Object interceptShiroSecurity(InvocationContext context) throws Exception {
        init(context);  // Since @PostConstruct isn't allowed in Weld 2.x

        Class<?> classType = context.getTarget().getClass();
        Method method = context.getMethod();

        supportForAsynchronousEJB(context, method);

        AccessDecisionVoterContext accessContext = new CustomAccessDecissionVoterContext(context);

        AnnotationInfo info = AnnotationUtil.getAllAnnotations(config, classType, method);

        // We need to check at 2 levels, method and then if not present at class level
        Set<Annotation> annotations = info.getMethodAnnotations();

        // This method can throw already a OctopusUnauthorizedException
        boolean accessAllowed = annotationAuthorizationChecker.checkAccess(annotations, accessContext);

        if (!accessAllowed) {
            // OK, at method level we didn't find any annotations.
            annotations = info.getClassAnnotations();

            // This method can throw already a OctopusUnauthorizedException
            accessAllowed = annotationAuthorizationChecker.checkAccess(annotations, accessContext);

        }
        if (!accessAllowed) {
            // Ok at classLevel also no info -> Exception
            throw new OctopusUnauthorizedException("No Authorization requirements available", infoProducer.getViolationInfo(accessContext));
        }
        return context.proceed();
    }

    private void supportForAsynchronousEJB(InvocationContext context, Method method) {
        Asynchronous asynchronous = method.getAnnotation(Asynchronous.class);
        if (asynchronous != null) {
            for (Object parameter : context.getParameters()) {

                if (parameter != null && OctopusSecurityContext.class.isAssignableFrom(parameter.getClass())) {
                    Subject subject = ((OctopusSecurityContext) parameter).getSubject();
                    ThreadContext.bind(subject);
                }
            }
        }
    }

}
