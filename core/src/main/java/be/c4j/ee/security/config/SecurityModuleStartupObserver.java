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
package be.c4j.ee.security.config;

import org.apache.myfaces.extensions.cdi.core.api.startup.event.StartupEvent;
import org.apache.myfaces.extensions.cdi.core.impl.AbstractStartupObserver;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;
import java.util.logging.Level;

@ApplicationScoped
public class SecurityModuleStartupObserver extends AbstractStartupObserver {

    @Inject
    private SecurityModuleConfig securityModuleConfig;

    protected SecurityModuleStartupObserver() {
    }

    protected void logSecurityModuleConfiguration(@Observes StartupEvent startupEvent) {
        try {
            StringBuilder info = new StringBuilder("[Started] Octopus framework (C4J) ");
            info.append(separator);

            //module config
            info.append(getConfigInfo(securityModuleConfig));
            logger.info(info.toString());
        }
        //avoid that this log harms the startup
        catch (Exception e) {
            logger.log(Level.WARNING,
                    "Octopus Module couldn't log the current configuration. Startup will continue!", e);
        }

    }

}
