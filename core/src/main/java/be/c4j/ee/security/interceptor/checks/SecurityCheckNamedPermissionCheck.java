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
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.config.VoterNameFactory;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import be.c4j.ee.security.permission.GenericPermissionVoter;
import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.util.AnnotationUtil;
import be.c4j.ee.security.util.CDIUtil;
import org.apache.deltaspike.core.api.provider.BeanManagerProvider;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;
import org.apache.shiro.subject.Subject;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import java.lang.annotation.Annotation;
import java.util.HashSet;
import java.util.Set;

/**
 * SecurityCheck for the annotation defined by OctopusConfig.getNamedPermissionCheckClass()
 */
@ApplicationScoped
public class SecurityCheckNamedPermissionCheck implements SecurityCheck {

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    @Inject
    private OctopusConfig config;

    @Inject
    private VoterNameFactory nameFactory;

    @Override
    public SecurityCheckInfo performCheck(Subject subject, AccessDecisionVoterContext accessContext, Annotation securityAnnotation) {
        SecurityCheckInfo result;

        if (!subject.isAuthenticated() && !subject.isRemembered()) {  // When login from remember me, the isAuthenticated return false
            result = SecurityCheckInfo.withException(
                    new OctopusUnauthorizedException("User required", infoProducer.getViolationInfo(accessContext))
            );
        } else {
            Set<SecurityViolation> securityViolations = performNamedPermissionChecks(securityAnnotation, accessContext);
            if (!securityViolations.isEmpty()) {
                result = SecurityCheckInfo.withException(
                        new OctopusUnauthorizedException(securityViolations));
            } else {
                result = SecurityCheckInfo.allowAccess();
            }
        }


        return result;
    }

    private Set<SecurityViolation> performNamedPermissionChecks(Annotation customNamedCheck, AccessDecisionVoterContext context) {
        Set<SecurityViolation> result = new HashSet<SecurityViolation>();

        BeanManager beanmanager = BeanManagerProvider.getInstance().getBeanManager();

        Combined permissionCombination = AnnotationUtil.getPermissionCombination(customNamedCheck);
        boolean onePermissionGranted = false;
        for (Object permissionConstant : AnnotationUtil.getPermissionValues(customNamedCheck)) {
            String beanName = nameFactory.generatePermissionBeanName(((NamedPermission) permissionConstant).name());

            GenericPermissionVoter voter = CDIUtil.getContextualReferenceByName(beanmanager, beanName
                    , GenericPermissionVoter.class);
            Set<SecurityViolation> violations = voter.checkPermission(context);
            if (violations.isEmpty()) {
                onePermissionGranted = true;
            }
            result.addAll(violations);

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
        return config.getNamedPermissionCheckClass() != null && config.getNamedPermissionCheckClass().isAssignableFrom(annotation.getClass());
    }
}
