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

package be.c4j.ee.security.view.startup;

import be.c4j.ee.security.view.interceptor.PermissionInterceptor;
import org.apache.myfaces.extensions.cdi.core.api.startup.event.StartupEvent;
import org.apache.myfaces.extensions.validator.core.ExtValContext;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

/**
 * @author Rudy De Busscher
 */
@ApplicationScoped
public class SecureComponentStartupListener {

    @Inject
    private PermissionInterceptor permissionInterceptor;

    protected void init(@Observes StartupEvent startupEvent) {
        ExtValContext.getContext().registerRendererInterceptor(permissionInterceptor);
    }
}
