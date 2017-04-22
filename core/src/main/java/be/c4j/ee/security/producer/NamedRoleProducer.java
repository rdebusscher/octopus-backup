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
package be.c4j.ee.security.producer;

import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.config.VoterNameFactory;
import be.c4j.ee.security.realm.OctopusRoles;
import be.c4j.ee.security.role.GenericRoleVoter;
import be.c4j.ee.security.role.NamedApplicationRole;
import be.c4j.ee.security.role.NamedRole;
import be.c4j.ee.security.role.RoleLookup;
import be.c4j.ee.security.util.AnnotationUtil;
import be.c4j.ee.security.util.CDIUtil;
import org.apache.deltaspike.core.api.provider.BeanManagerProvider;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.AmbiguousResolutionException;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.UnsatisfiedResolutionException;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.inject.Inject;
import java.lang.annotation.Annotation;

@ApplicationScoped
public class NamedRoleProducer {

    @Inject
    private OctopusConfig config;

    @Inject
    private VoterNameFactory nameFactory;

    private RoleLookup<? extends NamedRole> lookup;

    @PostConstruct
    public void init() {
        // Optional to make sure that if the bean is not created without actually needing it, we don't get into trouble if the lookup isn't defined.
        lookup = CDIUtil.getOptionalBean(RoleLookup.class);
    }

    @Produces
    public GenericRoleVoter getVoter(InjectionPoint injectionPoint) {
        GenericRoleVoter result = null;

        Annotation annotation = null;

        Class<? extends Annotation> namedRoleCheckClass = config.getNamedRoleCheckClass();
        if (namedRoleCheckClass != null) {
            annotation = injectionPoint.getAnnotated().getAnnotation(namedRoleCheckClass);
        }

        if (annotation != null) {
            NamedRole[] roles = AnnotationUtil.getRoleValues(annotation);
            if (roles.length > 1) {
                throw new AmbiguousResolutionException("Only one named role can be specified.");
            }

            result = CDIUtil.getContextualReferenceByName(BeanManagerProvider.getInstance().getBeanManager(), nameFactory
                    .generateRoleBeanName(roles[0].name()), GenericRoleVoter.class);

        }

        if (result == null) {
            annotation = injectionPoint.getAnnotated().getAnnotation(OctopusRoles.class);
            if (annotation != null) {
                String[] roleNames = AnnotationUtil.getStringValues(annotation);
                if (roleNames.length > 1) {
                    throw new AmbiguousResolutionException("Only one role can be specified."); // FIXME Specify at which InjectionPoint
                }


                NamedApplicationRole namedRole = null;
                if (lookup != null) {
                    namedRole = lookup.getRole(roleNames[0]);
                }
                if (namedRole == null) {
                    namedRole = new NamedApplicationRole(roleNames[0]);
                }

                result = GenericRoleVoter.createInstance(namedRole);
            }
        }

        if (result == null) {
            throw new UnsatisfiedResolutionException(
                    "Injection points for GenericRoleVoter needs an additional " + getInjectPointAnnotationText() +
                            " annotation to determine the correct bean");
        }

        return result;
    }

    private String getInjectPointAnnotationText() {
        StringBuilder result = new StringBuilder();
        result.append(OctopusRoles.class.getName());
        if (config.getNamedRoleCheckClass() != null) {
            result.append(" or ").append(config.getNamedRoleCheckClass().getName());
        }
        return result.toString();
    }

    @Produces
    public NamedApplicationRole getRole(InjectionPoint injectionPoint) {
        NamedApplicationRole result = null;

        Annotation annotation = null;

        Class<? extends Annotation> namedRoleCheckClass = config.getNamedRoleCheckClass();
        if (namedRoleCheckClass != null) {
            annotation = injectionPoint.getAnnotated().getAnnotation(namedRoleCheckClass);
        }

        if (annotation != null) {
            NamedRole[] roles = AnnotationUtil.getRoleValues(annotation);
            if (roles.length > 1) {
                throw new AmbiguousResolutionException("Only one named role can be specified.");
            }

            // With getNamedRoleCheckClass defined, the roleLookup is also required
            result = lookup.getRole(roles[0].name());

        }

        if (result == null) {
            annotation = injectionPoint.getAnnotated().getAnnotation(OctopusRoles.class);
            if (annotation != null) {
                String[] roleNames = AnnotationUtil.getStringValues(annotation);
                if (roleNames.length > 1) {
                    throw new AmbiguousResolutionException("Only one role can be specified."); // FIXME Specify at which InjectionPoint
                }

                if (lookup != null) {
                    result = lookup.getRole(roleNames[0]);
                }
                if (result == null) {
                    result = new NamedApplicationRole(roleNames[0]);
                }

            }
        }
        if (result == null) {
            throw new UnsatisfiedResolutionException(
                    "Injection points for NamedApplicationRole needs an additional " + getInjectPointAnnotationText() +
                            " annotation to determine the correct bean");
        }

        return result;

    }

}
