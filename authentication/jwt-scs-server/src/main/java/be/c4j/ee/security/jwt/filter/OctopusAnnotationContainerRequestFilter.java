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

import be.c4j.ee.security.CustomAccessDecissionVoterContext;
import be.c4j.ee.security.OctopusInvocationContext;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import be.c4j.ee.security.interceptor.AnnotationInfo;
import be.c4j.ee.security.octopus.AnnotationAuthorizationChecker;
import be.c4j.ee.security.util.AnnotationUtil;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;

import javax.inject.Inject;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Set;

/**
 * This cannot be moved to for example Oauth2-common as it is Java EE 6 based.
 * ContainerRequestFilter only available in Java EE 7.
 */
@Provider
public class OctopusAnnotationContainerRequestFilter implements ContainerRequestFilter {

    @Context
    private ResourceInfo resourceInfo;

    @Inject
    private OctopusConfig config;

    @Inject
    private AnnotationAuthorizationChecker annotationAuthorizationChecker;

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        Class<?> classType = resourceInfo.getResourceClass();
        Method method = resourceInfo.getResourceMethod();

        // TODO Is the OctopusInvocationContext a good idea here?
        OctopusInvocationContext context = new OctopusInvocationContext(method, null);
        AccessDecisionVoterContext accessContext = new CustomAccessDecissionVoterContext(context);

        AnnotationInfo info = AnnotationUtil.getAllAnnotations(config, classType, method);

        boolean skip = AnnotationUtil.hasAnnotation(info.getMethodAnnotations(), IgnoreOctopusSSORestFilter.class)
                || AnnotationUtil.hasAnnotation(info.getClassAnnotations(), IgnoreOctopusSSORestFilter.class);

        // Developer can indicate that the Authorization checks shouldn't happen here :
        // - JAX-RS endpoint is defined as an EJB
        // - Endpoint is used by other application which is not Octopus based and thus we don't have the authorization enforcements

        if (!skip) {

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
        }

    }
}
