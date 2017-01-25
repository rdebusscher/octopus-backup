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
package be.c4j.ee.security.view.component.secured;

import be.c4j.ee.security.config.VoterNameFactory;
import be.c4j.ee.security.view.component.ComponentUtil;
import be.c4j.ee.security.view.component.service.ComponentAuthorizationService;

import javax.enterprise.context.ApplicationScoped;
import javax.faces.component.UIComponent;
import javax.faces.component.UIParameter;
import javax.inject.Inject;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class OctopusHandlerHelper {

    @Inject
    private ComponentAuthorizationService componentAuthorizationService;

    @Inject
    private VoterNameFactory voterNameFactory;

    public SecuredComponentData gatherSecurityInfo(UIComponent component, UIComponent parent) {
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

        SecuredComponentData result = new SecuredComponentData(voter, not, combined, parameters, target);

        result.setAllTargetComponents(targets);

        return result;
    }

    private String getVoterName(UIComponent component) {
        StringBuilder result = new StringBuilder();
        String voter = ComponentUtil.findValue(component, "voter", String.class);
        appendVoterNames(result, voter);
        String permission = ComponentUtil.findValue(component, "permission", String.class);
        if (permission != null && permission.length() != 0) {
            voter = voterNameFactory.generatePermissionBeanName(permission);
            appendVoterNames(result, voter);
        }
        String role = ComponentUtil.findValue(component, "role", String.class);
        if (role != null && role.length() != 0) {
            voter = voterNameFactory.generateRoleBeanName(role);
            appendVoterNames(result, voter);
        }
        return result.toString();
    }

    private void appendVoterNames(StringBuilder result, String voter) {
        if (voter != null && !voter.trim().isEmpty()) {
            if (result.length() > 0) {
                result.append(", ");
            }
            result.append(voter);
        }
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

    public boolean hasAccess(SecuredComponentData data) {
        return componentAuthorizationService.hasAccess(data);
    }
}
