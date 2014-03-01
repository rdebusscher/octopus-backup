/*
 *
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * /
 */

package be.c4j.ee.security.view.component.service;

import be.c4j.ee.security.view.InvocationContextImpl;
import be.c4j.ee.security.view.component.SecuredComponentData;
import be.c4j.ee.security.view.component.SecuredComponentDataParameter;
import org.apache.myfaces.extensions.cdi.core.api.provider.BeanManagerProvider;
import org.apache.myfaces.extensions.cdi.core.api.security.AbstractAccessDecisionVoter;
import org.apache.myfaces.extensions.cdi.core.api.security.SecurityViolation;
import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.el.ValueExpression;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.spi.BeanManager;
import javax.faces.context.FacesContext;
import javax.interceptor.InvocationContext;
import java.util.NoSuchElementException;
import java.util.Set;

/**
 * @author Rudy De Busscher
 */
@ApplicationScoped
public class ComponentAuthorizationService {

    private final Logger logger = LoggerFactory.getLogger(getClass().getName());

    private BeanManager beanManager;

    public ComponentAuthorizationService() {
        beanManager = BeanManagerProvider.getInstance().getBeanManager();
    }

    public boolean hasAccess(final SecuredComponentData secureComponentData) {
        boolean result = secureComponentData.isCombined();
        boolean partialResult;
        Object[] contextParameters = getContextParameters(secureComponentData);
        for (String voter : secureComponentData.getVoters()) {
            AbstractAccessDecisionVoter bean = getBean(voter.trim());

            if (bean == null) {
                return false;
            }
            InvocationContext ic = new InvocationContextImpl(secureComponentData
                    .getTargetComponent(), contextParameters);
            Set<SecurityViolation> securityViolations = bean.checkPermission(ic);

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

    private AbstractAccessDecisionVoter getBean(final String name) {
        AbstractAccessDecisionVoter result = null;
        try {
            result = CodiUtils.getContextualReferenceByName(beanManager, name, AbstractAccessDecisionVoter.class);
        } catch (NoSuchElementException e) {
            logger.warn("The AccessDecisionVoter with name " + name + " is not found.");
        }
        return result;
    }

    private static Object evaluateExpression(final String valueExpression) {
        FacesContext facesContext = FacesContext.getCurrentInstance();
        ValueExpression expression = facesContext.getApplication().getExpressionFactory()
                                                 .createValueExpression(facesContext
                                                         .getELContext(), valueExpression, Object.class);
        return expression.getValue(facesContext.getELContext());
    }

}