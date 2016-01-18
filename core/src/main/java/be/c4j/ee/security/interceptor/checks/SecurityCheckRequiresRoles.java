/*
 * Copyright 2014-2016 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.interceptor.checks;

import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.lang.annotation.Annotation;

/**
 *
 */
@ApplicationScoped
public class SecurityCheckRequiresRoles implements SecurityCheck {

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    @Override
    public SecurityCheckInfo performCheck(Subject subject, AccessDecisionVoterContext accessContext, Annotation securityAnnotation) {
        SecurityCheckInfo result;

        RequiresRoles requiresRoles = (RequiresRoles) securityAnnotation;
        String[] roles = requiresRoles.value();
        try {
            subject.checkRoles(roles);
            result = SecurityCheckInfo.allowAccess();
        } catch (AuthorizationException ae) {
            result = SecurityCheckInfo.withException(
                    new OctopusUnauthorizedException("Shiro Roles required", infoProducer.getViolationInfo(accessContext))
            );
        }
        return result;
    }

    @Override
    public boolean hasSupportFor(Object annotation) {
        return RequiresRoles.class.isAssignableFrom(annotation.getClass());
    }
}
