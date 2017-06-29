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
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.StringPermissionLookup;
import be.c4j.ee.security.realm.OctopusPermissions;
import be.c4j.ee.security.util.AnnotationUtil;
import be.c4j.ee.security.util.CDIUtil;
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
 * SecurityCheck for the annotation @OctopusPermissions which takes String permission (named, wildcard or short version)
 */
@ApplicationScoped
public class SecurityCheckOctopusPermission implements SecurityCheck {

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    private StringPermissionLookup stringPermissionLookup;

    private Map<String, NamedDomainPermission> permissionCache;

    @PostConstruct
    public void init() {
        // StringPermissionProvider is optional, created by a Producer.
        stringPermissionLookup = CDIUtil.getOptionalBean(StringPermissionLookup.class);

        permissionCache = new HashMap<String, NamedDomainPermission>();
    }

    @Override
    public SecurityCheckInfo performCheck(Subject subject, AccessDecisionVoterContext accessContext, Annotation securityAnnotation) {
        SecurityCheckInfo result;

        if (!subject.isAuthenticated() && !subject.isRemembered()) {  // When login from remember me, the isAuthenticated return false
            result = SecurityCheckInfo.withException(
                    new OctopusUnauthorizedException("User required", infoProducer.getViolationInfo(accessContext))
            );
        } else {
            Set<SecurityViolation> securityViolations = performPermissionChecks(securityAnnotation, subject, accessContext);
            if (!securityViolations.isEmpty()) {
                result = SecurityCheckInfo.withException(
                        new OctopusUnauthorizedException(securityViolations));
            } else {
                result = SecurityCheckInfo.allowAccess();
            }
        }


        return result;
    }

    private Set<SecurityViolation> performPermissionChecks(Annotation octopusPermission, Subject subject, AccessDecisionVoterContext accessContext) {
        Set<SecurityViolation> result = new HashSet<SecurityViolation>();

        Combined permissionCombination = AnnotationUtil.getPermissionCombination(octopusPermission);
        boolean onePermissionGranted = false;
        NamedDomainPermission permission;
        for (String permissionString : AnnotationUtil.getStringValues(octopusPermission)) {
            if (stringPermissionLookup != null) {
                permission = stringPermissionLookup.getPermission(permissionString);
                // TODO What if we specify a String value which isn't defined in the lookup?
            } else {
                permission = permissionCache.get(permissionString);
                if (permission == null) {
                    if (!permissionString.contains(":")) {
                        permissionString += ":*:*";
                    }
                    permission = new NamedDomainPermission(StringPermissionLookup.createNameForPermission(permissionString), permissionString);
                    permissionCache.put(permissionString, permission);
                }

            }


            if (subject.isPermitted(permission)) {
                onePermissionGranted = true;
            } else {
                InvocationContext invocationContext = accessContext.getSource();
                result.add(infoProducer.defineOctopusViolation(invocationContext, permission));
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
        return OctopusPermissions.class.isAssignableFrom(annotation.getClass());
    }
}
