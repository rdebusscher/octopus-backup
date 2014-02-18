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
package be.c4j.ee.security.shiro;

import be.c4j.ee.security.config.SecurityModuleConfig;
import org.apache.myfaces.extensions.cdi.core.api.provider.BeanManagerProvider;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.config.Ini;
import org.apache.shiro.web.config.IniFilterChainResolverFactory;
import org.apache.shiro.web.env.IniWebEnvironment;

public class CompoundWebEnvironment extends IniWebEnvironment {

    private static final String APP_URL = "";

    private SecurityModuleConfig securityModuleConfig;

    @Override
    public void init() {
        // securityModuleConfig used by setIni which is called by super.init().
        securityModuleConfig = BeanManagerProvider.getInstance().getContextualReference(SecurityModuleConfig.class);
        super.init();
    }

    @Override
    public void setIni(Ini ini) {

        try {
            Ini iniWithURLS = getSpecifiedIni(new String[]{securityModuleConfig.getLocationSecuredURLProperties()});

            iniWithURLS.setSectionProperty(APP_URL, "/**", "anon");
            ini.put(IniFilterChainResolverFactory.URLS, iniWithURLS.getSection(APP_URL));
        } catch (ConfigurationException ex) {
            ;// FIXME Logging
        }

        super.setIni(ini);
    }
}
