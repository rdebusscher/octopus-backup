package be.c4j.ee.security.producer;

import be.c4j.ee.security.config.SecurityModuleConfig;
import be.c4j.ee.security.config.VoterNameFactory;
import be.c4j.ee.security.permission.GenericPermissionVoter;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.permission.PermissionLookup;
import be.c4j.ee.security.util.AnnotationUtil;
import org.apache.myfaces.extensions.cdi.core.api.provider.BeanManagerProvider;
import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;

import javax.enterprise.inject.AmbiguousResolutionException;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.UnsatisfiedResolutionException;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.inject.Inject;
import java.lang.annotation.Annotation;

public class NamedPermissionProducer {

    @Inject
    private SecurityModuleConfig config;

    @Inject
    private VoterNameFactory nameFactory;

    @Inject
    private PermissionLookup<? extends NamedPermission> lookup;

    @Produces
    public GenericPermissionVoter getVoter(InjectionPoint injectionPoint) {
        Annotation annotation = injectionPoint.getAnnotated().getAnnotation(config.getNamedPermissionCheckClass());
        if (annotation == null) {
            throw new UnsatisfiedResolutionException(
                    "Injection points for GenericPermissionVoter needs an additional " + config.getNamedPermissionCheck() +
                            " annotation to determine the correct bean");
        }
        NamedPermission[] permissions = AnnotationUtil.getValue(annotation);
        if (permissions.length>1) {
            throw new AmbiguousResolutionException("Only one named permission can be specified.");
        }


        return CodiUtils.getContextualReferenceByName(BeanManagerProvider.getInstance().getBeanManager(), nameFactory
                .generatePermissionBeanName(permissions[0].name()), GenericPermissionVoter.class);
    }

    @Produces
    public NamedDomainPermission getPermission(InjectionPoint injectionPoint) {
        Annotation annotation = injectionPoint.getAnnotated().getAnnotation(config.getNamedPermissionCheckClass());
        if (annotation == null) {
            throw new UnsatisfiedResolutionException(
                    "Injection points for NamedDomainPermission needs an additional " + config.getNamedPermissionCheck() +
                            " annotation to determine the correct bean");
        }
        NamedPermission[] permissions = AnnotationUtil.getValue(annotation);
        if (permissions.length>1) {
            throw new AmbiguousResolutionException("Only one named permission can be specified.");
        }

        return lookup.getPermission(permissions[0].name());

    }

}
