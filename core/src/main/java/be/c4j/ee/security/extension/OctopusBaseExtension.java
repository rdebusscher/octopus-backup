package be.c4j.ee.security.extension;

import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.config.VoterNameFactory;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.permission.GenericPermissionVoter;
import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.permission.PermissionLookup;
import be.c4j.ee.security.role.GenericRoleVoter;
import be.c4j.ee.security.role.NamedRole;
import be.c4j.ee.security.role.RoleLookup;
import be.c4j.ee.security.util.CDIUtil;
import org.apache.deltaspike.core.api.literal.NamedLiteral;
import org.apache.deltaspike.core.util.bean.BeanBuilder;
import org.apache.deltaspike.core.util.metadata.builder.DelegatingContextualLifecycle;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.inject.spi.*;

/**
 *
 */
public class OctopusBaseExtension implements Extension {

    protected OctopusConfig config;
    protected VoterNameFactory nameFactory;

    protected void createPermissionVoters(AfterBeanDiscovery afterBeanDiscovery, BeanManager beanManager) {


        Class<? extends NamedPermission> namedPermissionClass = config.getNamedPermissionClass();

        if (namedPermissionClass != null) {

            Object[] constants = namedPermissionClass.getEnumConstants();

            AnnotatedType<GenericPermissionVoter> permissionVoterAnnotatedType = beanManager
                    .createAnnotatedType(GenericPermissionVoter.class);
            InjectionTarget<GenericPermissionVoter> voterInjectionTarget = beanManager
                    .createInjectionTarget(permissionVoterAnnotatedType);

            NamedPermission namedPermission;
            String beanName;

            for (Object permission : constants) {
                namedPermission = (NamedPermission) permission;
                beanName = nameFactory.generatePermissionBeanNameForExtension(namedPermission.name());

                Bean<GenericPermissionVoter> bean = new BeanBuilder<GenericPermissionVoter>(beanManager)
                        .passivationCapable(false).beanClass(GenericPermissionVoter.class)
                        .injectionPoints(voterInjectionTarget.getInjectionPoints()).name(beanName)
                        .scope(ApplicationScoped.class).qualifiers(new NamedLiteral(beanName))
                        .beanLifecycle(new PermissionLifecycleCallback(voterInjectionTarget, namedPermission)).create();
                afterBeanDiscovery.addBean(bean);
            }
        }
    }

    protected void createRoleVoters(AfterBeanDiscovery afterBeanDiscovery, BeanManager beanManager) {

        Class<? extends NamedRole> namedRoleClass = config.getNamedRoleClass();

        if (namedRoleClass != null) {

            Object[] constants = namedRoleClass.getEnumConstants();

            AnnotatedType<GenericRoleVoter> roleVoterAnnotatedType = beanManager
                    .createAnnotatedType(GenericRoleVoter.class);
            InjectionTarget<GenericRoleVoter> voterInjectionTarget = beanManager
                    .createInjectionTarget(roleVoterAnnotatedType);

            NamedRole namedRole;
            String beanName;

            for (Object permission : constants) {
                namedRole = (NamedRole) permission;
                beanName = nameFactory.generateRoleBeanName(namedRole.name());

                Bean<GenericRoleVoter> bean = new BeanBuilder<GenericRoleVoter>(beanManager)
                        .passivationCapable(false).beanClass(GenericRoleVoter.class)
                        .injectionPoints(voterInjectionTarget.getInjectionPoints()).name(beanName)
                        .scope(ApplicationScoped.class).qualifiers(new NamedLiteral(beanName))
                        .beanLifecycle(new RoleLifecycleCallback(voterInjectionTarget, namedRole)).create();
                afterBeanDiscovery.addBean(bean);
            }
        }
    }

    private static class PermissionLifecycleCallback extends DelegatingContextualLifecycle<GenericPermissionVoter> {

        private NamedPermission namedPermission;

        public PermissionLifecycleCallback(InjectionTarget<GenericPermissionVoter> injectionTarget, NamedPermission
                someNamedPermission) {
            super(injectionTarget);
            namedPermission = someNamedPermission;
        }

        @Override
        public GenericPermissionVoter create(Bean<GenericPermissionVoter> bean,
                                             CreationalContext<GenericPermissionVoter> creationalContext) {
            GenericPermissionVoter result = super.create(bean, creationalContext);

            // We can't move this to the Extension itself.
            // The producer of this PermissionLookup goes to the database and this isn't possible until we are completely ready.

            PermissionLookup<? extends NamedPermission> permissionLookup = CDIUtil.getOptionalBean(PermissionLookup.class);
            if (permissionLookup == null) {
                throw new OctopusConfigurationException("When using the named permissions, please configure them with the PermissionLookup.  See manual ??? TODO");
            }
            result.setNamedPermission(permissionLookup.getPermission(namedPermission.name()));
            return result;
        }

        @Override
        public void destroy(Bean<GenericPermissionVoter> bean, GenericPermissionVoter instance,
                            CreationalContext<GenericPermissionVoter> creationalContext) {
            super.destroy(bean, instance, creationalContext);
        }
    }

    private static class RoleLifecycleCallback extends DelegatingContextualLifecycle<GenericRoleVoter> {

        private NamedRole namedRole;

        public RoleLifecycleCallback(InjectionTarget<GenericRoleVoter> injectionTarget, NamedRole
                someNamedRole) {
            super(injectionTarget);
            namedRole = someNamedRole;
        }

        @Override
        public GenericRoleVoter create(Bean<GenericRoleVoter> bean,
                                       CreationalContext<GenericRoleVoter> creationalContext) {
            GenericRoleVoter result = super.create(bean, creationalContext);

            // We can't move this to the Extension itself.
            // The producer of this RoleLookup goes to the database and this isn't possible until we are completely ready.
            RoleLookup<? extends NamedRole> roleLookup = CDIUtil.getOptionalBean(RoleLookup.class);
            if (roleLookup == null) {
                throw new OctopusConfigurationException("When using the named roles, please configure them with the RoleLookup.  See manual ??? TODO");
            }

            result.setNamedRole(roleLookup.getRole(namedRole.name()));
            return result;
        }

        @Override
        public void destroy(Bean<GenericRoleVoter> bean, GenericRoleVoter instance,
                            CreationalContext<GenericRoleVoter> creationalContext) {
            super.destroy(bean, instance, creationalContext);
        }
    }


}
