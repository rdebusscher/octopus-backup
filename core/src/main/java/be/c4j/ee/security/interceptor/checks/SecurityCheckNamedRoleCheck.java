/*
 * Copyright 2014-2015 Rudy De Busscher (www.c4j.be)
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

import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.config.VoterNameFactory;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import be.c4j.ee.security.permission.GenericPermissionVoter;
import be.c4j.ee.security.role.NamedRole;
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
public class SecurityCheckNamedRoleCheck implements SecurityCheck {

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    @Inject
    private OctopusConfig config;

    @Inject
    private VoterNameFactory nameFactory;

    @Override
    public SecurityCheckInfo performCheck(Subject subject, AccessDecisionVoterContext accessContext, Annotation securityAnnotation) {
        SecurityCheckInfo result;

        if (subject.getPrincipal() == null) {
            result = SecurityCheckInfo.withException(
                    new OctopusUnauthorizedException("User required", infoProducer.getViolationInfo(accessContext))
            );
        } else {
            Set<SecurityViolation> securityViolations = performNamedRoleChecks(securityAnnotation, accessContext);
            if (!securityViolations.isEmpty()) {

                result = SecurityCheckInfo.withException(
                        new OctopusUnauthorizedException(securityViolations));
            } else {
                result = SecurityCheckInfo.allowAccess();
            }
        }


        return result;
    }

    private Set<SecurityViolation> performNamedRoleChecks(Annotation customNamedCheck, AccessDecisionVoterContext context) {
        Set<SecurityViolation> result = new HashSet<SecurityViolation>();

        BeanManager beanmanager = BeanManagerProvider.getInstance().getBeanManager();

        for (Object permissionConstant : AnnotationUtil.getRoleValues(customNamedCheck)) {
            String beanName = nameFactory.generateRoleBeanName(((NamedRole) permissionConstant).name());

            GenericPermissionVoter voter = CDIUtil.getContextualReferenceByName(beanmanager, beanName
                    , GenericPermissionVoter.class);
            result.addAll(voter.checkPermission(context));

        }
        return result;
    }

    @Override
    public boolean hasSupportFor(Object annotation) {
        return config.getNamedRoleCheckClass() != null && config.getNamedRoleCheckClass().isAssignableFrom(annotation.getClass());
    }
}
