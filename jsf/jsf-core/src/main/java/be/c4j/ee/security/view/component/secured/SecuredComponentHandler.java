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
 *
 */
package be.c4j.ee.security.view.component.secured;

import be.c4j.ee.security.util.JsfUtils;
import be.c4j.ee.security.view.component.ComponentUtil;
import be.c4j.ee.security.view.component.OctopusComponentHandler;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.faces.component.UIComponent;
import javax.faces.view.facelets.ComponentConfig;

/**
 *
 */
public class SecuredComponentHandler extends OctopusComponentHandler {

    private OctopusHandlerHelper octopusHandlerHelper;

    public SecuredComponentHandler(ComponentConfig config) {
        super(config);
    }

    @Override
    protected void handleComponentSecurity(UIComponent component, UIComponent parent) {
        checkServices();

        SecuredComponentData data = octopusHandlerHelper.gatherSecurityInfo(component, parent);

        if (JsfUtils.isRenderResponsePhase() && !data.hasAtRuntimeParameter()) {

            if (!octopusHandlerHelper.hasAccess(data)) {
                for (UIComponent targetComponent : data.getAllTargetComponents()) {
                    SecuredComponentData dataForTarget = new SecuredComponentData(data);
                    dataForTarget.setTargetComponent(targetComponent);
                    ComponentUtil.setNoAccess(targetComponent, dataForTarget);
                }
            }
        } else {
            for (UIComponent targetComponent : data.getAllTargetComponents()) {
                SecuredComponentData dataForTarget = new SecuredComponentData(data);
                dataForTarget.setTargetComponent(targetComponent);

                targetComponent.getAttributes().put(SecuredComponent.DATA, dataForTarget);
            }
        }
    }

    private void checkServices() {
        if (octopusHandlerHelper == null) {
            octopusHandlerHelper = BeanProvider.getContextualReference(OctopusHandlerHelper.class);
        }
    }

}
