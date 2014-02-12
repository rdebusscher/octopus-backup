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

package be.c4j.ee.security.view.component;

import be.c4j.ee.security.view.component.service.PermissionService;
import org.apache.myfaces.extensions.validator.util.JsfUtils;

import javax.el.ValueExpression;
import javax.faces.component.UIComponent;
import javax.faces.component.UIParameter;
import javax.faces.context.FacesContext;
import javax.faces.event.PreRenderViewEvent;
import javax.faces.event.SystemEvent;
import javax.faces.event.SystemEventListener;
import javax.faces.view.facelets.ComponentConfig;
import javax.faces.view.facelets.ComponentHandler;
import javax.faces.view.facelets.FaceletContext;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Rudy De Busscher
 */
public class SecuredComponentHandler extends ComponentHandler {
    private static PermissionService permissionService;

    public SecuredComponentHandler(ComponentConfig config) {
        super(config);
    }

    @Override
    public void onComponentPopulated(FaceletContext ctx, UIComponent component, UIComponent parent) {
        super.onComponentPopulated(ctx, component, parent);
        String voter = findValue(component, "voter", String.class);
        Boolean not = findValue(component, "not", Boolean.class);
        if (not == null) {
            not = Boolean.FALSE;
        }
        Boolean combined = findValue(component, "combined", Boolean.class);
        if (combined == null) {
            combined = Boolean.FALSE;
        }
        String target = findValue(component, "for", String.class);

        List<UIComponent> targets = findTargets(component, parent, target);

        SecuredComponentDataParameter[] parameters = findParameters(component);

        SecuredComponentData data = new SecuredComponentData(voter, not, combined, parameters, target);

        if (JsfUtils.isRenderResponsePhase() && !data.hasAtRuntimeParameter()) {

            checkPermissionService();
            if (!permissionService.hasAccess(data)) {
                for (UIComponent targetComponent : targets) {
                    SecuredComponentData dataForTarget = new SecuredComponentData(data);
                    dataForTarget.setTargetComponent(targetComponent);
                    setNoAccess(targetComponent, dataForTarget);
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

    private static void setNoAccess(final UIComponent targetComponent, final SecuredComponentData dataForTarget) {
        targetComponent.setRendered(false);
        targetComponent.getAttributes().put(SecuredComponent.MARKER, Boolean.TRUE);
        targetComponent.getAttributes().put(SecuredComponent.DATA, dataForTarget);
    }

    private static List<UIComponent> findTargets(final UIComponent component, final UIComponent parent,
                                                 final String target) {
        List<UIComponent> result = new ArrayList<UIComponent>();
        if (target == null || target.length() == 0) {
            result.add(parent);
        } else {
            UIComponent targetComponent;
            String[] targets = target.split(",");
            for (String targetId : targets) {
                targetComponent = lookupComponentInTree(parent, targetId.trim());
                if (targetComponent != null) {
                    result.add(targetComponent);
                } else {
                    if (isInCustomComponent(parent)) {
                        FacesContext.getCurrentInstance().getViewRoot().subscribeToViewEvent(PreRenderViewEvent
                                .class, new RelocateSecurityInformationEventListener(component));
                        result.add(component);
                    } else {
                        System.out.println(targetId + " not found");   // FIXME
                    }
                }
            }
        }
        return result;
    }

    private static UIComponent lookupComponentInTree(UIComponent parent, String targetId) {
        UIComponent targetComponent = null;
        if (parent != null) {
            targetComponent = parent.findComponent(targetId);
            if (targetComponent == null) {
                return lookupComponentInTree(parent.getParent(), targetId);
            }
        }
        return targetComponent;
    }

    private static boolean isInCustomComponent(final UIComponent uiComponent) {
        boolean result = false;
        if (uiComponent != null && uiComponent.getParent() != null && uiComponent.getParent().getAttributes() != null) {
            result = uiComponent.getParent().getAttributes()
                                .containsKey("javax.faces.application.Resource.ComponentResource");
        }
        return result;
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

    private <T> T findValue(UIComponent component, String valueName, Class<T> resultClass) {
        T result = null;

        if (component.getAttributes().containsKey(valueName)) {
            if (Boolean.class.equals(resultClass)) {
                // He, maybe it should be possible to store the correct type in the attributes.  We specified it in
                // the taglib.xml
                result = (T) new Boolean((String) component.getAttributes().get(valueName));
            } else {
                result = (T) component.getAttributes().get(valueName);
            }
        }
        if (result == null) {
            ValueExpression ve = component.getValueExpression(valueName);
            if (ve != null) {
                result = (T) ve.getValue(FacesContext.getCurrentInstance().getELContext());
            }
        }
        return result;
    }

    private static void checkPermissionService() {
        if (permissionService == null) {
            permissionService = new PermissionService();
        }
    }

    private static class RelocateSecurityInformationEventListener implements SystemEventListener {

        private UIComponent component;

        private RelocateSecurityInformationEventListener(UIComponent someComponent) {
            component = someComponent;
        }

        @Override
        public boolean isListenerForSource(Object source) {
            return true;
        }

        @Override
        public void processEvent(SystemEvent event) {
            SecuredComponentData data = (SecuredComponentData) component.getAttributes().get(SecuredComponent.DATA);
            if (data == null) {
                // We have a PreRenderViewEvent defined in the screen.
                return;
            }
            List<UIComponent> targets = findTargets(component, component.getParent(), data.getTargets());
            if (component.getAttributes().containsKey(SecuredComponent.MARKER)) {
                for (UIComponent targetComponent : targets) {
                    SecuredComponentData dataForTarget = new SecuredComponentData(data);
                    dataForTarget.setTargetComponent(targetComponent);

                    setNoAccess(targetComponent, dataForTarget);
                }
            } else {
                for (UIComponent targetComponent : targets) {
                    targetComponent.getAttributes().put(SecuredComponent.DATA, data);
                }
            }
        }
    }
}
