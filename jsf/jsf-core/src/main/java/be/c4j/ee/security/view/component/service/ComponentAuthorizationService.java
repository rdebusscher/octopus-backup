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
package be.c4j.ee.security.view.component.service;

import be.c4j.ee.security.CustomAccessDecissionVoterContext;
import be.c4j.ee.security.permission.GenericPermissionVoter;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.StringPermissionLookup;
import be.c4j.ee.security.util.CDIUtil;
import be.c4j.ee.security.view.component.secured.SecuredComponentData;
import be.c4j.ee.security.view.component.secured.SecuredComponentDataParameter;
import org.apache.deltaspike.core.api.provider.BeanManagerProvider;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.deltaspike.security.api.authorization.AbstractAccessDecisionVoter;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;
import org.slf4j.Logger;

import javax.annotation.PostConstruct;
import javax.el.ValueExpression;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.spi.BeanManager;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import java.util.NoSuchElementException;
import java.util.Set;

/**
 *
 */
@ApplicationScoped
public class ComponentAuthorizationService {

    @Inject
    private Logger logger;

    private BeanManager beanManager;

    private StringPermissionLookup stringLookup;

    @PostConstruct
    public void init() {
        beanManager = BeanManagerProvider.getInstance().getBeanManager();
        // StringPermissionLookup is Optional
        stringLookup = BeanProvider.getContextualReference(StringPermissionLookup.class, true);
    }

    public boolean hasAccess(SecuredComponentData secureComponentData) {
        boolean result = secureComponentData.isCombined();
        boolean partialResult;
        Object[] contextParameters = getContextParameters(secureComponentData);
        for (String voter : secureComponentData.getVoters()) {
            AbstractAccessDecisionVoter bean = getBean(voter.trim());

            if (bean == null) {
                return false;
            }
            AccessDecisionVoterContext context = new CustomAccessDecissionVoterContext(secureComponentData
                    .getTargetComponent(), contextParameters);
            Set<SecurityViolation> securityViolations = bean.checkPermission(context);

            partialResult = securityViolations.isEmpty();
            if (secureComponentData.isNot()) {
                partialResult = !partialResult;
            }
            result = partialResult;
            if (!secureComponentData.isCombined()) {
                if (result) {
                    return true;
                }
            } else {
                if (!result) {
                    return false;
                }
            }
        }
        return result;
    }

    private Object[] getContextParameters(SecuredComponentData secureComponentData) {
        if (secureComponentData.getParameters() == null) {
            return new Object[0];
        }
        Object[] result = new Object[secureComponentData.getParameters().length];
        int idx = 0;
        for (SecuredComponentDataParameter parameter : secureComponentData.getParameters()) {
            if (parameter.isAtRuntime()) {
                result[idx++] = evaluateExpression((String) parameter.getParameterData());
            } else {
                result[idx++] = parameter.getParameterData();
            }
        }
        return result;
    }

    private AbstractAccessDecisionVoter getBean(String name) {
        AbstractAccessDecisionVoter result = null;

        if (name.contains(":")) {
            NamedDomainPermission permission;
            if (name.startsWith(":")) {
                // Remove the leading :
                String realName = name.substring(1);
                if (stringLookup == null) {
                    // We found a name but developer didn't specify some lookup. So assume :*:* at the end

                    permission = new NamedDomainPermission(StringPermissionLookup.createNameForPermission(realName), realName + ":*:*");
                } else {
                    permission = stringLookup.getPermission(realName);
                }
            } else {
                // TODO During testing we found out that x:y fails, need to perform checks everywhere
                // A full blown wildcard shiro permission
                permission = new NamedDomainPermission(StringPermissionLookup.createNameForPermission(name), name);
            }
            result = GenericPermissionVoter.createInstance(permission);

        } else {
            try {
                result = CDIUtil.getContextualReferenceByName(beanManager, name, AbstractAccessDecisionVoter.class);
            } catch (NoSuchElementException e) {
                logger.warn("The AccessDecisionVoter with name " + name + " is not found.");
            }
        }
        return result;
    }

    private static Object evaluateExpression(String valueExpression) {
        FacesContext facesContext = FacesContext.getCurrentInstance();
        ValueExpression expression = facesContext.getApplication().getExpressionFactory()
                .createValueExpression(facesContext
                        .getELContext(), valueExpression, Object.class);
        return expression.getValue(facesContext.getELContext());
    }

}