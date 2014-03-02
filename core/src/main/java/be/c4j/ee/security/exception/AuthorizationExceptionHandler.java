/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package be.c4j.ee.security.exception;

import be.c4j.ee.security.config.SecurityModuleConfig;
import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;
import org.apache.shiro.authz.UnauthorizedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.faces.FacesException;
import javax.faces.application.FacesMessage;
import javax.faces.application.NavigationHandler;
import javax.faces.context.ExceptionHandler;
import javax.faces.context.ExceptionHandlerWrapper;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.event.ExceptionQueuedEvent;
import javax.faces.event.ExceptionQueuedEventContext;
import java.io.IOException;
import java.util.Iterator;
import java.util.Map;

public class AuthorizationExceptionHandler extends ExceptionHandlerWrapper {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationExceptionHandler.class.getCanonicalName());

    private ExceptionHandler wrapped;

    AuthorizationExceptionHandler(ExceptionHandler exception) {
        this.wrapped = exception;
    }

    @Override
    public ExceptionHandler getWrapped() {
        return wrapped;
    }

    @Override
    public void handle() throws FacesException {

        Iterator<ExceptionQueuedEvent> i = getUnhandledExceptionQueuedEvents().iterator();
        while (i.hasNext()) {
            ExceptionQueuedEvent event = i.next();
            ExceptionQueuedEventContext context = (ExceptionQueuedEventContext) event.getSource();

            // get the exception from context
            Throwable t = context.getException();

            FacesContext facesContext = FacesContext.getCurrentInstance();
            ExternalContext externalContext = facesContext.getExternalContext();
            Map<String, Object> requestMap = externalContext.getRequestMap();
            NavigationHandler nav = facesContext.getApplication().getNavigationHandler();

            Throwable unauthorized = getUnauthorizedException(t);
            //here you do what ever you want with exception
            if (unauthorized != null) {
                try {

                    //log error ?
                    LOGGER.error("Critical Exception!", t);

                    externalContext.getFlash().setKeepMessages(true);
                    facesContext.addMessage(null,
                            new FacesMessage(FacesMessage.SEVERITY_ERROR, unauthorized.getMessage(), unauthorized.getMessage()));

                    if (unauthorized instanceof OctopusUnauthorizedException) {

                        externalContext.getFlash().putNow("interceptionInfo", ((OctopusUnauthorizedException) unauthorized ) .getExceptionPointInfo());
                    }
                    try {
                        SecurityModuleConfig config = CodiUtils.getContextualReferenceByClass(SecurityModuleConfig.class);
                        externalContext.redirect(externalContext.getRequestContextPath() + config.getUnauthorizedExceptionPage());

                    } catch (IOException e) {
                        LOGGER.error("Redirect to unauthorized page failed", e);
                    }
                    facesContext.renderResponse();


                } finally {
                    //remove it from queue
                    i.remove();
                }
            }
        }
        //parent handle
        getWrapped().handle();
    }

    private Throwable getUnauthorizedException(Throwable someException) {
        Throwable result = null;
        if (someException instanceof UnauthorizedException) {
            result = someException;
        } else {
            if (someException.getCause() != null) {
                result = getUnauthorizedException(someException.getCause());
            }
        }
        return result;
    }

}