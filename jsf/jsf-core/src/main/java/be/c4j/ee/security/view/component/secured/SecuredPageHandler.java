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

import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.faces.component.UIComponent;
import javax.faces.component.UIViewRoot;
import javax.faces.context.ExternalContext;
import javax.faces.view.facelets.*;
import java.io.IOException;

/**
 *
 */
public class SecuredPageHandler extends OctopusTagHandler {

    public SecuredPageHandler(TagConfig config) {
        super(config);
    }

    @Override
    void handleSecurity(FaceletContext ctx, UIComponent parent, SecuredComponentData securedComponentData) {
        if (!octopusHandlerHelper.hasAccess(securedComponentData)) {
            ctx.getFacesContext().responseComplete();

            OctopusJSFConfig config = BeanProvider.getContextualReference(OctopusJSFConfig.class);
            ExternalContext externalContext = ctx.getFacesContext().getExternalContext();
            try {
                externalContext.redirect(externalContext.getRequestContextPath() + config.getUnauthorizedExceptionPage());
            } catch (IOException e) {
                // OWASP A6 : Sensitive Data Exposure
                throw new OctopusUnexpectedException(e);
            }

        }
    }
}
