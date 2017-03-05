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
package be.c4j.ee.security.octopus;

import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.interceptor.checks.AnnotationCheckFactory;
import be.c4j.ee.security.interceptor.checks.SecurityCheckInfo;
import be.c4j.ee.security.util.AnnotationUtil;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

import javax.annotation.security.PermitAll;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.lang.annotation.Annotation;
import java.util.Iterator;
import java.util.Set;

/**
 *
 */
@ApplicationScoped
public class AnnotationAuthorizationChecker {

    @Inject
    private AnnotationCheckFactory annotationCheckFactory;

    public boolean checkAccess(Set<Annotation> annotations, AccessDecisionVoterContext accessContext) {
        OctopusUnauthorizedException exception = null;
        boolean accessAllowed = false;

        if (!annotations.isEmpty()) {
            if (AnnotationUtil.hasAnnotation(annotations, PermitAll.class)) {
                accessAllowed = true;
            } else {
                Subject subject = SecurityUtils.getSubject();
                Iterator<Annotation> annotationIterator = annotations.iterator();

                while (!accessAllowed && annotationIterator.hasNext()) {
                    Annotation annotation = annotationIterator.next();
                    SecurityCheckInfo checkInfo = annotationCheckFactory.getCheck(annotation).performCheck(subject, accessContext, annotation);
                    if (checkInfo.isAccessAllowed()) {
                        accessAllowed = true;
                    }
                    if (checkInfo.getException() != null) {
                        exception = checkInfo.getException();
                    }

                }
            }
            if (!accessAllowed && exception != null) {
                throw exception;
            }
        }

        return accessAllowed;
    }

}
