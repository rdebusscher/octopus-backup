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

import org.apache.myfaces.extensions.validator.core.interceptor.RendererInterceptor;
import org.apache.myfaces.extensions.validator.core.renderkit.exception.SkipAfterInterceptorsException;
import org.apache.myfaces.extensions.validator.core.renderkit.exception.SkipBeforeInterceptorsException;
import org.apache.myfaces.extensions.validator.core.renderkit.exception.SkipRendererDelegationException;

import javax.enterprise.context.ApplicationScoped;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.convert.ConverterException;
import javax.faces.render.Renderer;
import javax.inject.Inject;
import java.io.IOException;

/**
 * @author Rudy De Busscher
 */
@ApplicationScoped
public class PermissionInterceptor implements RendererInterceptor {

    @Inject
    private SecuredRuntimeManager securedRuntimeManager;

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

        securedRuntimeManager.checkRendererStatus(uiComponent);
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
        securedRuntimeManager.resetRenderedStatus(uiComponent);
    }

    @Override
    public void afterGetConvertedValue(final FacesContext facesContext, final UIComponent uiComponent,
                                       final Object submittedValue, final Renderer renderer) throws
            ConverterException, SkipAfterInterceptorsException {
        // No implementation required.
    }

}
