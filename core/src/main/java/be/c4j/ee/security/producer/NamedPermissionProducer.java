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
import be.c4j.ee.security.permission.*;
import be.c4j.ee.security.realm.OctopusPermissions;
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
public class NamedPermissionProducer extends AbstractProducer {

    @Inject
    private OctopusConfig config;

    @Inject
    private VoterNameFactory nameFactory;

    private PermissionLookup<? extends NamedPermission> lookup;

    private StringPermissionLookup stringLookup;

    @PostConstruct
    public void init() {
        // True to make sure that if the bean is created without actually needing it, we don't get into trouble if the lookup isn't defined.
        lookup = CDIUtil.getOptionalBean(PermissionLookup.class);

        stringLookup = CDIUtil.getOptionalBean(StringPermissionLookup.class);
        if (stringLookup == null) {
            // Developer hasn't defined a producer for it, so let create an instance with no mapped permissions.
            // So they need to use always wildcardStrings!!
            stringLookup = new StringPermissionLookup();
        }
    }

    @Produces
    public GenericPermissionVoter getVoter(InjectionPoint injectionPoint) {
        NamedPermission[] permissions;

        GenericPermissionVoter result = null;

        if (config.getNamedPermissionCheckClass() != null) {
            Annotation annotation = injectionPoint.getAnnotated().getAnnotation(config.getNamedPermissionCheckClass());
            if (annotation != null) {
                permissions = AnnotationUtil.getPermissionValues(annotation);
                if (permissions.length > 1) {
                    throw new AmbiguousResolutionException(String.format("Only one named permission can be specified at %s", defineInjectionPointInfo(injectionPoint)));
                }
                result = CDIUtil.getContextualReferenceByName(BeanManagerProvider.getInstance().getBeanManager(), nameFactory
                        .generatePermissionBeanName(permissions[0].name()), GenericPermissionVoter.class);
            }
        }

        if (result == null) {
            Annotation annotation = injectionPoint.getAnnotated().getAnnotation(OctopusPermissions.class);
            if (annotation != null) {

                String[] stringPermissions = AnnotationUtil.getStringValues(annotation);
                if (stringPermissions.length > 1) {
                    throw new AmbiguousResolutionException(String.format("Only one named permission can be specified at %s", defineInjectionPointInfo(injectionPoint)));
                }

                // See remarks at init() about the usage of StringLookup, even if the developer hasn't defined one
                NamedDomainPermission permission = stringLookup.getPermission(stringPermissions[0]);

                // TODO CDI Bean is dependent, can we cache it here since it could be application scoped but then we can't change NamedDomainPermission

                result = GenericPermissionVoter.createInstance(permission);
            }
        }

        if (result == null) {

            throw new UnsatisfiedResolutionException(
                    String.format("Injection points for GenericPermissionVoter needs an additional %s annotation to determine the correct bean at %s"
                            , getInjectPointAnnotationText(), defineInjectionPointInfo(injectionPoint))
            );
        }

        return result;
    }

    @Produces
    public NamedDomainPermission getPermission(InjectionPoint injectionPoint) {
        Class<? extends Annotation> namedPermissionCheckClass = config.getNamedPermissionCheckClass();

        NamedDomainPermission result = null;

        if (namedPermissionCheckClass != null) {

            Annotation annotation = injectionPoint.getAnnotated().getAnnotation(namedPermissionCheckClass);

            if (annotation != null) {
                NamedPermission[] permissions = AnnotationUtil.getPermissionValues(annotation);
                if (permissions.length > 1) {
                    throw new AmbiguousResolutionException(String.format("Only one named permission can be specified at %s", defineInjectionPointInfo(injectionPoint)));
                }

                // When we have NamedPermissionCheckClass, lookup is required.
                result = lookup.getPermission(permissions[0].name());
            }
        }

        if (result == null) {
            Annotation annotation = injectionPoint.getAnnotated().getAnnotation(OctopusPermissions.class);
            if (annotation != null) {

                String[] stringPermissions = AnnotationUtil.getStringValues(annotation);
                if (stringPermissions.length > 1) {
                    throw new AmbiguousResolutionException(String.format("Only one named permission can be specified at %s", defineInjectionPointInfo(injectionPoint)));
                }

                // See remarks at init() about the usage of StringLookup, even if the developer hasn't defined one
                result = stringLookup.getPermission(stringPermissions[0]);
            }
        }

        if (result == null) {
            throw new UnsatisfiedResolutionException(
                    String.format("Injection points for NamedDomainPermission needs an additional %s annotation to determine the correct bean at %s"
                            , getInjectPointAnnotationText(), defineInjectionPointInfo(injectionPoint))
            );
        }

        return result;
    }

    private String getInjectPointAnnotationText() {
        StringBuilder result = new StringBuilder();
        result.append(OctopusPermissions.class.getName());
        if (config.getNamedPermissionCheckClass() != null) {
            result.append(" or ").append(config.getNamedPermissionCheckClass().getName());
        }
        return result.toString();
    }

}
