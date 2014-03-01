package be.c4j.ee.security.producer;

import be.c4j.ee.security.config.SecurityModuleConfig;
import be.c4j.ee.security.config.VoterNameFactory;
import be.c4j.ee.security.permission.GenericPermissionVoter;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.permission.PermissionLookup;
import be.c4j.ee.security.role.GenericRoleVoter;
import be.c4j.ee.security.role.NamedApplicationRole;
import be.c4j.ee.security.role.NamedRole;
import be.c4j.ee.security.role.RoleLookup;
import be.c4j.ee.security.util.AnnotationUtil;
import org.apache.myfaces.extensions.cdi.core.api.provider.BeanManagerProvider;
import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;

import javax.enterprise.inject.AmbiguousResolutionException;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.UnsatisfiedResolutionException;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.inject.Inject;
import java.lang.annotation.Annotation;

public class NamedRoleProducer {

    @Inject
    private SecurityModuleConfig config;

    @Inject
    private VoterNameFactory nameFactory;

    @Inject
    private RoleLookup<? extends NamedRole> lookup;

    @Produces
    public GenericRoleVoter getVoter(InjectionPoint injectionPoint) {
        Annotation annotation = injectionPoint.getAnnotated().getAnnotation(config.getNamedRoleCheckClass());
        if (annotation == null) {
            throw new UnsatisfiedResolutionException(
                    "Injection points for GenericRoleVoter needs an additional " + config.getNamedRoleCheck() +
                            " annotation to determine the correct bean");
        }
        NamedRole[] roles = AnnotationUtil.getRoleValues(annotation);
        if (roles.length>1) {
            throw new AmbiguousResolutionException("Only one named role can be specified.");
        }


        return CodiUtils.getContextualReferenceByName(BeanManagerProvider.getInstance().getBeanManager(), nameFactory
                .generateRoleBeanName(roles[0].name()), GenericRoleVoter.class);
    }

    @Produces
    public NamedApplicationRole getRole(InjectionPoint injectionPoint) {
        Annotation annotation = injectionPoint.getAnnotated().getAnnotation(config.getNamedRoleCheckClass());
        if (annotation == null) {
            throw new UnsatisfiedResolutionException(
                    "Injection points for NamedApplicationRole needs an additional " + config.getNamedPermissionCheck() +
                            " annotation to determine the correct bean");
        }
        NamedRole[] roles = AnnotationUtil.getRoleValues(annotation);
        if (roles.length>1) {
            throw new AmbiguousResolutionException("Only one named role can be specified.");
        }

        return lookup.getRole(roles[0].name());

    }

}