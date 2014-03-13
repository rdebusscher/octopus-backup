package be.c4j.ee.security.octopus.primefaces;

import be.c4j.ee.security.view.interceptor.SecuredRuntimeManager;
import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;
import org.primefaces.component.api.UIColumn;
import org.primefaces.component.datatable.DataTable;
import org.primefaces.component.datatable.DataTableRenderer;

import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
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
        if (column.isRendered() && securedRuntimeManager.allowed((UIComponent) column)) {

        super.encodeCell(context, table, column, clientId, selected);
        }
    }
}
