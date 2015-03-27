/*
 * Copyright 2014-2015 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.octopus.primefaces;

import be.c4j.ee.security.view.interceptor.SecuredRuntimeManager;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.primefaces.component.column.Column;
import org.primefaces.component.datagrid.DataGridRenderer;

import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import java.io.IOException;

/**
 *
 */
public class OctopusDataGridRenderer extends DataGridRenderer {

    private SecuredRuntimeManager securedRuntimeManager;

    public OctopusDataGridRenderer() {
        securedRuntimeManager = BeanProvider.getContextualReference(SecuredRuntimeManager.class);
    }

    @Override
    protected void renderChild(FacesContext context, UIComponent child) throws IOException {
        if (child instanceof Column) {
            if (child.isRendered() && securedRuntimeManager.allowed(child)) {

                super.renderChild(context, child);
            }
        } else {
            super.renderChild(context, child);
        }
    }
}
