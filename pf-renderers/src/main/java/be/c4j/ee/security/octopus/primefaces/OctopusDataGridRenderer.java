package be.c4j.ee.security.octopus.primefaces;

import be.c4j.ee.security.view.interceptor.SecuredRuntimeManager;
import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;
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
        securedRuntimeManager = CodiUtils.getContextualReferenceByClass(SecuredRuntimeManager.class);
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
