/*
 * Copyright 2014-2017 Rudy De Busscher (www.c4j.be)
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
 */
package be.c4j.ee.security.credentials.authentication.oauth2;

import be.c4j.ee.security.credentials.authentication.oauth2.application.ApplicationInfo;
import be.c4j.ee.security.shiro.OctopusUserFilter;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.ShiroException;
import org.apache.shiro.util.Initializable;

/**
 *
 */
public class OAuth2UserFilter extends OctopusUserFilter implements Initializable {

    private ApplicationInfo applicationInfo;
    private OAuth2ServletInfo oAuth2ServletInfo;

    @Override
    public String getLoginUrl() {
        String result = "";

        if (applicationInfo != null) {
            result = '?' + OAuth2Configuration.APPLICATION + '=' + applicationInfo.getName();
        }

        return oAuth2ServletInfo.getServletPath() + result;
    }

    @Override
    public void init() throws ShiroException {
        applicationInfo = BeanProvider.getContextualReference(ApplicationInfo.class, true);
        oAuth2ServletInfo = BeanProvider.getContextualReference(OAuth2ServletInfo.class);
    }
}
