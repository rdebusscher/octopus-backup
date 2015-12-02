package be.c4j.ee.security.view.component.secured;

import be.c4j.ee.security.util.JsfUtils;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.el.MethodExpression;
import javax.el.ValueExpression;
import javax.faces.component.UIComponent;
import javax.faces.component.UIComponentBase;
import javax.faces.view.facelets.FaceletContext;
import javax.faces.view.facelets.TagAttribute;
import javax.faces.view.facelets.TagConfig;
import javax.faces.view.facelets.TagHandler;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public class PermissionListenerHandler extends TagHandler {

    private static final String[] PERMISSION_LISTENR_ATTRIBUTES = new String[]{"voter", "permission", "role", "not", "combined", "for", "listener"};

    private OctopusHandlerHelper octopusHandlerHelper;

    public PermissionListenerHandler(TagConfig config) {
        super(config);
    }

    @Override
    public void apply(FaceletContext ctx, UIComponent parent) throws IOException {

        checkServices();

        SecuredComponentData data = octopusHandlerHelper.gatherSecurityInfo(new ComponentAroundTagHandler(ctx, this), parent);


        if (octopusHandlerHelper.hasAccess(data)) {

            MethodExpression listener = JsfUtils.createMethodExpression(getAttribute("listener").getValue(), Void.class, UIComponent.class);
            listener.invoke(ctx.getFacesContext().getELContext(), new Object[]{parent});
        }

    }

    private TagAttribute getAttributeCallback(String name) {
        return getAttribute(name);
    }

    private void checkServices() {
        if (octopusHandlerHelper == null) {
            octopusHandlerHelper = BeanProvider.getContextualReference(OctopusHandlerHelper.class);
        }
    }

    public static class ComponentAroundTagHandler extends UIComponentBase {

        private Map<String, Object> attributes = new HashMap<String, Object>();
        private Map<String, ValueExpression> valueExpressions = new HashMap<String, ValueExpression>();

        public ComponentAroundTagHandler(FaceletContext ctx, PermissionListenerHandler tagHandler) {

            for (String attributeName : PERMISSION_LISTENR_ATTRIBUTES) {
                TagAttribute attribute = tagHandler.getAttributeCallback(attributeName);
                if (attribute != null) {
                    String value = attribute.getValue();

                    if (valueExpression(value)) {
                        if (!methodExpression(value)) {
                            valueExpressions.put(attributeName, attribute.getValueExpression(ctx, Object.class));
                        }
                    } else {
                        attributes.put(attributeName, value);
                    }
                }
            }
        }

        private boolean methodExpression(String value) {
            return value.endsWith(")}");
        }

        private boolean valueExpression(String value) {
            return value.contains("#{");
        }

        @Override
        public String getFamily() {
            return "Fake";
        }

        @Override
        public Map<String, Object> getAttributes() {
            return attributes;
        }

        @Override
        public ValueExpression getValueExpression(String s) {
            return valueExpressions.get(s);
        }
    }
}
