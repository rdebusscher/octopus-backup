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
package be.c4j.ee.security.view.component;

import be.c4j.ee.security.view.component.secured.SecuredComponent;
import be.c4j.ee.security.view.component.secured.SecuredComponentData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.el.ValueExpression;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.event.PreRenderViewEvent;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public final class ComponentUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(ComponentUtil.class);

    private ComponentUtil() {
    }

    public static <T> T findValue(UIComponent component, String valueName, Class<T> resultClass) {
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

    public static void setNoAccess(final UIComponent targetComponent, final SecuredComponentData dataForTarget) {
        targetComponent.setRendered(false);
        targetComponent.getAttributes().put(SecuredComponent.MARKER, Boolean.TRUE);
        if (dataForTarget != null) {

            targetComponent.getAttributes().put(SecuredComponent.DATA, dataForTarget);
        }
    }

    public static List<UIComponent> findTargets(final UIComponent component, final UIComponent parent,
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
                        LOGGER.warn("Unable to find component with ID " + targetId + " in view.");
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
}
