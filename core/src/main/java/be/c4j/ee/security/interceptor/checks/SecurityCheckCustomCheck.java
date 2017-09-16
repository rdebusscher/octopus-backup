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

import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.config.VoterNameFactory;
import be.c4j.ee.security.custom.AbstractGenericVoter;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import be.c4j.ee.security.permission.OctopusPermissionResolver;
import be.c4j.ee.security.shiro.OctopusSecurityManager;
import be.c4j.ee.security.util.AnnotationUtil;
import org.apache.deltaspike.core.api.provider.BeanManagerProvider;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;
import org.apache.deltaspike.security.spi.authorization.EditableAccessDecisionVoterContext;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import java.lang.annotation.Annotation;
import java.util.HashSet;
import java.util.Set;

/**
 * SecurityCheck for the annotation defined by OctopusConfig.getCustomCheckClass().
 */
@ApplicationScoped
public class SecurityCheckCustomCheck implements SecurityCheck {

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    @Inject
    private OctopusConfig config;

    @Inject
    private VoterNameFactory nameFactory;

    @Inject
    private OctopusPermissionResolver permissionResolver;

    @Override
    public SecurityCheckInfo performCheck(Subject subject, AccessDecisionVoterContext accessContext, Annotation securityAnnotation) {
        SecurityCheckInfo result;

        if (!subject.isAuthenticated()) {
            result = SecurityCheckInfo.withException(
                    new OctopusUnauthorizedException("User required", infoProducer.getViolationInfo(accessContext))
            );
        } else {
            // TODO Check on EditableAccessDecisionVoterContext (maybe check immediatly on OctopusAccessDecisionVoterContext ??)
            Set<SecurityViolation> securityViolations = performCustomCheck(subject, securityAnnotation, (EditableAccessDecisionVoterContext) accessContext);
            if (!securityViolations.isEmpty()) {
                result = SecurityCheckInfo.withException(
                        new OctopusUnauthorizedException(securityViolations));
            } else {
                result = SecurityCheckInfo.allowAccess();
            }
        }

        return result;
    }

    private Set<SecurityViolation> performCustomCheck(Subject subject, Annotation customCheck, EditableAccessDecisionVoterContext context) {
        Set<SecurityViolation> result = new HashSet<SecurityViolation>();

        String beanName = nameFactory.generateCustomCheckBeanName(customCheck.annotationType().getSimpleName());

        AbstractGenericVoter voter = (AbstractGenericVoter) BeanProvider.getContextualReference(beanName, true);
        if (voter == null) {
            throw new OctopusConfigurationException(String.format("An AbstractGenericVoter CDI bean with name %s cannot be found. Custom check annotation feature requirement", beanName));
        }

        if (!AnnotationUtil.hasAdvancedFlag(customCheck)) {

            SecurityManager securityManager = SecurityUtils.getSecurityManager();
            if (securityManager instanceof OctopusSecurityManager) {
                OctopusSecurityManager octopusSecurityManager = (OctopusSecurityManager) securityManager;
                String[] permissionStringValue = AnnotationUtil.getStringValues(customCheck);
                if (permissionStringValue == null || permissionStringValue.length != 1) {
                    throw new IllegalArgumentException(String.format("value member of %s annotation can only have a single String value", customCheck.annotationType().getName()));
                }
                Permission permission = permissionResolver.resolvePermission(permissionStringValue[0]);
                context.addMetaData(Permission.class.getName(), octopusSecurityManager.getPermissions(subject, permission));
            }
            // TODO Probably throw some error when we have another SecurityManager
        }

        Set<SecurityViolation> violations = voter.checkPermission(context);
        result.addAll(violations);

        return result;
    }


    @Override
    public boolean hasSupportFor(Object annotation) {
        return config.getCustomCheckClass() != null && config.getCustomCheckClass().isAssignableFrom(annotation.getClass());
    }
}
