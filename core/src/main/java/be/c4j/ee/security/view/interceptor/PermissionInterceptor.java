/*
 *
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * /
 */

package be.c4j.ee.security.view.interceptor;

import be.c4j.ee.security.view.component.SecuredComponent;
import be.c4j.ee.security.view.component.SecuredComponentData;
import be.c4j.ee.security.view.component.service.ComponentAuthorizationService;
import org.apache.myfaces.extensions.validator.core.interceptor.RendererInterceptor;
import org.apache.myfaces.extensions.validator.core.renderkit.exception.SkipAfterInterceptorsException;
import org.apache.myfaces.extensions.validator.core.renderkit.exception.SkipBeforeInterceptorsException;
import org.apache.myfaces.extensions.validator.core.renderkit.exception.SkipRendererDelegationException;

import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.convert.ConverterException;
import javax.faces.render.Renderer;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Rudy De Busscher
 */
public class PermissionInterceptor implements RendererInterceptor {

    private Set<UIComponent> componentSet = new HashSet<UIComponent>();

    private ComponentAuthorizationService componentAuthorizationService;

    @Override
    public String getInterceptorId() {
        return "CodiPermissionInterceptor";
    }

    @Override
    public Object getReturnValueOnSkipRendererDelegationException(final SkipRendererDelegationException
                                                                              skipRendererDelegationException,
                                                                  final Object currentReturnValue) {
        return null;
    }

    @Override
    public void beforeDecode(final FacesContext facesContext, final UIComponent uiComponent,
                             final Renderer renderer) throws SkipBeforeInterceptorsException,
            SkipRendererDelegationException {
        // No implementation required.
    }

    @Override
    public void beforeEncodeBegin(final FacesContext facesContext, final UIComponent uiComponent,
                                  final Renderer renderer) throws IOException, SkipBeforeInterceptorsException,
            SkipRendererDelegationException {

        if (uiComponent.isRendered() && !allowed(uiComponent)) {
            uiComponent.setRendered(false);
            // Keep an indication that we have changed the state.
            keepComponent(uiComponent);
            componentSet.add(uiComponent);
        }
    }

    private void keepComponent(UIComponent uiComponent) {
        String rendererType = uiComponent.getParent().getRendererType();
        if (rendererType == null) {
            uiComponent.getParent().setRendererType("Dummy");
        }
    }

    /**
     * If there exists a child in the component named SecuredComponent, the the user must have one of the permissions
     * specified in
     * the value attribute of the component.  If no child is found, the viewing is allowed.
     *
     * @param someUiComponent The JSF component we have to evaluate for security.
     * @return Is it allowed to show this component to the user.
     */
    private boolean allowed(final UIComponent someUiComponent) {

        boolean result = true;
        SecuredComponentData data = (SecuredComponentData) someUiComponent.getAttributes().get(SecuredComponent.DATA);
        if (data != null) {
            checkPermissionService();
            result = componentAuthorizationService.hasAccess(data);
        }
        return result;
    }

    @Override
    public void beforeEncodeChildren(final FacesContext facesContext, final UIComponent uiComponent,
                                     final Renderer renderer) throws IOException, SkipBeforeInterceptorsException,
            SkipRendererDelegationException {
        // No implementation required.
    }

    @Override
    public void beforeEncodeEnd(final FacesContext facesContext, final UIComponent uiComponent,
                                final Renderer renderer) throws IOException, SkipBeforeInterceptorsException,
            SkipRendererDelegationException {
        // No implementation required.
    }

    @Override
    public void beforeGetConvertedValue(final FacesContext facesContext, final UIComponent uiComponent,
                                        final Object submittedValue, final Renderer renderer) throws
            ConverterException, SkipBeforeInterceptorsException, SkipRendererDelegationException {
        // No implementation required.
    }

    @Override
    public void afterDecode(final FacesContext facesContext, final UIComponent uiComponent,
                            final Renderer renderer) throws SkipAfterInterceptorsException {
        // No implementation required.
    }

    @Override
    public void afterEncodeBegin(final FacesContext facesContext, final UIComponent uiComponent,
                                 final Renderer renderer) throws IOException, SkipAfterInterceptorsException {
        // No implementation required.
    }

    @Override
    public void afterEncodeChildren(final FacesContext facesContext, final UIComponent uiComponent,
                                    final Renderer renderer) throws IOException, SkipAfterInterceptorsException {
        // No implementation required.
    }

    @Override
    public void afterEncodeEnd(final FacesContext facesContext, final UIComponent uiComponent,
                               final Renderer renderer) throws IOException, SkipAfterInterceptorsException {
        // The afterEncodeEnd is not called for not rendered components.  So we catch here the afterEncodeEnd of the
        // parent.
        if (!componentSet.isEmpty()) {
            // Try to do something only when there is something to remove -> performance increase.
            for (UIComponent child : uiComponent.getChildren()) {
                if (componentSet.contains(child)) {
                    child.setRendered(true);
                    componentSet.remove(child);
                    if ("Dummy".equals(uiComponent.getRendererType())) {
                        uiComponent.setRendererType(null);
                    }
                }
            }
        }
    }

    @Override
    public void afterGetConvertedValue(final FacesContext facesContext, final UIComponent uiComponent,
                                       final Object submittedValue, final Renderer renderer) throws
            ConverterException, SkipAfterInterceptorsException {
        // No implementation required.
    }

    private void checkPermissionService() {
        if (componentAuthorizationService == null) {
            componentAuthorizationService = new ComponentAuthorizationService();
        }
    }

}
