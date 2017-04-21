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
package be.c4j.ee.security.interceptor.checks;

import be.c4j.ee.security.Combined;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import be.c4j.ee.security.realm.OctopusRoles;
import be.c4j.ee.security.role.NamedApplicationRole;
import be.c4j.ee.security.role.RoleLookup;
import be.c4j.ee.security.util.AnnotationUtil;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;
import org.apache.shiro.subject.Subject;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.interceptor.InvocationContext;
import java.lang.annotation.Annotation;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * SecurityCheck for the annotation @OctopusRoles which takes String (named or plain)
 */
@ApplicationScoped
public class SecurityCheckOctopusRole implements SecurityCheck {

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    private RoleLookup roleLookup;

    private Map<String, NamedApplicationRole> permissionCache;

    @PostConstruct
    public void init() {
        // StringPermissionProvider is optional.
        roleLookup = BeanProvider.getContextualReference(RoleLookup.class, true);

        permissionCache = new HashMap<String, NamedApplicationRole>();
    }

    @Override
    public SecurityCheckInfo performCheck(Subject subject, AccessDecisionVoterContext accessContext, Annotation securityAnnotation) {
        SecurityCheckInfo result;

        if (subject.getPrincipal() == null) {
            result = SecurityCheckInfo.withException(
                    new OctopusUnauthorizedException("User required", infoProducer.getViolationInfo(accessContext))
            );
        } else {
            Set<SecurityViolation> securityViolations = performRoleChecks(securityAnnotation, subject, accessContext);
            if (!securityViolations.isEmpty()) {
                result = SecurityCheckInfo.withException(
                        new OctopusUnauthorizedException(securityViolations));
            } else {
                result = SecurityCheckInfo.allowAccess();
            }
        }


        return result;
    }

    private Set<SecurityViolation> performRoleChecks(Annotation octopusPermission, Subject subject, AccessDecisionVoterContext accessContext) {
        Set<SecurityViolation> result = new HashSet<SecurityViolation>();
        Combined permissionCombination = AnnotationUtil.getPermissionCombination(octopusPermission);
        boolean onePermissionGranted = false;
        for (String roleName : AnnotationUtil.getStringValues(octopusPermission)) {
            NamedApplicationRole namedRole = null;
            if (roleLookup != null) {
                namedRole = roleLookup.getRole(roleName);
            }
            if (namedRole == null) {
                namedRole = permissionCache.get(roleName);
                if (namedRole == null) {
                    namedRole = new NamedApplicationRole(roleName);
                    permissionCache.put(roleName, namedRole);
                }
            }
            if (subject.isPermitted(namedRole)) {
                onePermissionGranted = true;
            } else {
                InvocationContext invocationContext = accessContext.getSource();
                result.add(infoProducer.defineOctopusViolation(invocationContext, namedRole));
            }
        }
        // When we have specified OR and there is one permissions which didn't result in some violations
        // Remove all the collected violations since access is granted.
        if (permissionCombination == Combined.OR && onePermissionGranted) {
            result.clear();
        }
        return result;
    }


    @Override
    public boolean hasSupportFor(Object annotation) {
        return OctopusRoles.class.isAssignableFrom(annotation.getClass());
    }
}
