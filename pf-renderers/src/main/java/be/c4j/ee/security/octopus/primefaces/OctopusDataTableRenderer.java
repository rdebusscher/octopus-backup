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
package be.c4j.ee.security.octopus.primefaces;

import be.c4j.ee.security.view.interceptor.SecuredRuntimeManager;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.primefaces.component.api.DynamicColumn;
import org.primefaces.component.api.UIColumn;
import org.primefaces.component.datatable.DataTable;
import org.primefaces.component.datatable.DataTableRenderer;

import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.context.ResponseWriter;
import java.io.IOException;

/**
 *
 */
public class OctopusDataTableRenderer extends DataTableRenderer {

    private SecuredRuntimeManager securedRuntimeManager;

    public OctopusDataTableRenderer() {
        securedRuntimeManager = BeanProvider.getContextualReference(SecuredRuntimeManager.class);
    }

    @Override
    protected void encodeCell(FacesContext context, DataTable table, UIColumn column, String clientId, boolean selected) throws IOException {
        if (column.isRendered()) {
            if (column instanceof DynamicColumn) {
                super.encodeCell(context, table, column, clientId, selected);
            } else {
                if (securedRuntimeManager.allowed((UIComponent) column)) {

                    super.encodeCell(context, table, column, clientId, selected);
                    securedRuntimeManager.resetRenderedStatus((UIComponent) column);
                } else {
                    renderEmptyCell(context);
                }
            }
        }
    }

    private void renderEmptyCell(FacesContext context) throws IOException {
        ResponseWriter writer = context.getResponseWriter();

        writer.startElement("td", null);
        writer.writeAttribute("role", "gridcell", null);
        writer.endElement("td");

    }

    @Override
    public boolean encodeRow(FacesContext context, DataTable table, String clientId, int rowIndex) throws IOException {
        boolean result = super.encodeRow(context, table, clientId, rowIndex);
        for (UIColumn column : table.getColumns()) {
            securedRuntimeManager.resetRenderedStatus((UIComponent) column);
        }

        return result;
    }
}
