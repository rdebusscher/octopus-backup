/*
 * Copyright 2014-2016 Rudy De Busscher (www.c4j.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package be.c4j.ee.security.sso.client;

import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.ee.security.shiro.OctopusUserFilter;
import be.rubus.web.jerry.config.DynamicConfigValueHelper;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.ShiroException;
import org.apache.shiro.util.Initializable;

/**
 *
 */
public class SSOOctopusUserFilter extends OctopusUserFilter implements Initializable {

    private DynamicConfigValueHelper valueHelper;
    private OctopusJSFConfig configuration;

    @Override
    public void init() throws ShiroException {
        valueHelper = BeanProvider.getContextualReference(DynamicConfigValueHelper.class);
        configuration = BeanProvider.getContextualReference(OctopusJSFConfig.class);
    }

    @Override
    public String getLoginUrl() {
        String loginURL = super.getLoginUrl();
        if (valueHelper.isDynamicValue(loginURL)) {
            loginURL = valueHelper.getCompleteConfigValue(configuration.getLoginPage());
        }
        return loginURL;
    }

}
