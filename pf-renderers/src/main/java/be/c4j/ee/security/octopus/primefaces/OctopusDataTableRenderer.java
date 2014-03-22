package be.c4j.ee.security.octopus.primefaces;

import be.c4j.ee.security.view.interceptor.SecuredRuntimeManager;
import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;
import org.primefaces.component.api.DynamicColumn;
import org.primefaces.component.api.UIColumn;
import org.primefaces.component.column.Column;
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
        securedRuntimeManager = CodiUtils.getContextualReferenceByClass(SecuredRuntimeManager.class);
    }

    @Override
    protected void encodeCell(FacesContext context, DataTable table, UIColumn column, String clientId, boolean selected) throws IOException {
        if (column.isRendered()) {
            if (securedRuntimeManager.allowed((UIComponent) column)) {

                super.encodeCell(context, table, column, clientId, selected);
            } else {
                renderEmptyCell(context);
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
