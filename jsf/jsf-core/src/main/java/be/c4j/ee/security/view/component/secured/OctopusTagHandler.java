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

import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.faces.component.UIComponent;
import javax.faces.view.facelets.FaceletContext;
import javax.faces.view.facelets.TagAttribute;
import javax.faces.view.facelets.TagConfig;
import javax.faces.view.facelets.TagHandler;
import java.io.IOException;

/**
 *
 */

public abstract class OctopusTagHandler extends TagHandler {

    protected OctopusHandlerHelper octopusHandlerHelper;

    public OctopusTagHandler(TagConfig config) {
        super(config);
    }

    @Override
    public void apply(FaceletContext ctx, UIComponent parent) throws IOException {

        checkServices();

        SecuredComponentData data = octopusHandlerHelper.gatherSecurityInfo(new ComponentAroundTagHandler(ctx, this), parent);

        handleSecurity(ctx, parent, data);

    }

    abstract void handleSecurity(FaceletContext ctx, UIComponent parent, SecuredComponentData securedComponentData);

    TagAttribute getAttributeCallback(String name) {
        return getAttribute(name);
    }

    private void checkServices() {
        if (octopusHandlerHelper == null) {
            octopusHandlerHelper = BeanProvider.getContextualReference(OctopusHandlerHelper.class);
        }
    }

}