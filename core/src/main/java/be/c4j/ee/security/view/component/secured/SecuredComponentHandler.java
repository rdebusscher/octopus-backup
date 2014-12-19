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

package be.c4j.ee.security.view.component.secured;

import be.c4j.ee.security.config.VoterNameFactory;
import be.c4j.ee.security.util.JsfUtils;
import be.c4j.ee.security.view.component.ComponentUtil;
import be.c4j.ee.security.view.component.OctopusComponentHandler;
import be.c4j.ee.security.view.component.service.ComponentAuthorizationService;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.faces.component.UIComponent;
import javax.faces.component.UIParameter;
import javax.faces.view.facelets.ComponentConfig;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Rudy De Busscher
 */
public class SecuredComponentHandler extends OctopusComponentHandler {

    // ComponentAuthorizationService is a CDI bean, but this bean is not CDI managed
    private ComponentAuthorizationService componentAuthorizationService;

    // VoterNameFactory is a CDI bean, but this bean is not CDI managed
    private VoterNameFactory voterNameFactory;

    public SecuredComponentHandler(ComponentConfig config) {
        super(config);
    }

    @Override
    protected void handleComponentSecurity(UIComponent component, UIComponent parent) {
        checkServices();

        String voter = getVoterName(component);

        Boolean not = ComponentUtil.findValue(component, "not", Boolean.class);
        if (not == null) {
            not = Boolean.FALSE;
        }
        Boolean combined = ComponentUtil.findValue(component, "combined", Boolean.class);
        if (combined == null) {
            combined = Boolean.FALSE;
        }
        String target = ComponentUtil.findValue(component, "for", String.class);

        List<UIComponent> targets = ComponentUtil.findTargets(component, parent, target);

        SecuredComponentDataParameter[] parameters = findParameters(component);

        SecuredComponentData data = new SecuredComponentData(voter, not, combined, parameters, target);

        if (!targets.isEmpty()) {
            data.setTargetComponent(targets.get(0));
        }
        if (JsfUtils.isRenderResponsePhase() && !data.hasAtRuntimeParameter()) {

            if (!componentAuthorizationService.hasAccess(data)) {
                for (UIComponent targetComponent : targets) {
                    SecuredComponentData dataForTarget = new SecuredComponentData(data);
                    dataForTarget.setTargetComponent(targetComponent);
                    ComponentUtil.setNoAccess(targetComponent, dataForTarget);
                }
            }
        } else {
            for (UIComponent targetComponent : targets) {
                SecuredComponentData dataForTarget = new SecuredComponentData(data);
                dataForTarget.setTargetComponent(targetComponent);

                targetComponent.getAttributes().put(SecuredComponent.DATA, dataForTarget);
            }
        }
    }

    private String getVoterName(UIComponent component) {
        String voter = ComponentUtil.findValue(component, "voter", String.class);
        if (voter == null || voter.length() == 0) {
            String permission = ComponentUtil.findValue(component, "permission", String.class);
            if (permission != null && permission.length() != 0) {
                voter = voterNameFactory.generatePermissionBeanName(permission);
            }
        }
        if (voter == null || voter.length() == 0) {
            String role = ComponentUtil.findValue(component, "role", String.class);
            if (role != null && role.length() != 0) {
                voter = voterNameFactory.generateRoleBeanName(role);
            }
        }
        return voter;
    }

    private SecuredComponentDataParameter[] findParameters(UIComponent c) {
        List<SecuredComponentDataParameter> result = new ArrayList<SecuredComponentDataParameter>();
        for (UIComponent child : c.getChildren()) {
            if (child instanceof UIParameter) {
                UIParameter uiParameter = (UIParameter) child;
                result.add(new SecuredComponentDataParameter(uiParameter.getValue()));
            }
            if (child instanceof SecuredComponentParameter) {
                SecuredComponentParameter parameter = (SecuredComponentParameter) child;
                result.add(new SecuredComponentDataParameter(parameter.getValueExpression("value")
                                                                      .getExpressionString(), true));
            }
        }

        return result.toArray(new SecuredComponentDataParameter[]{});
    }

    private void checkServices() {
        if (componentAuthorizationService == null) {
            componentAuthorizationService = BeanProvider.getContextualReference(ComponentAuthorizationService.class);
            voterNameFactory = BeanProvider.getContextualReference(VoterNameFactory.class);
        }
    }

}
