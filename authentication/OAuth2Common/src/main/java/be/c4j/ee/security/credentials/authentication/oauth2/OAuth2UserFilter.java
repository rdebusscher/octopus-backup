/*
 * Copyright 2014-2015 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.credentials.authentication.oauth2;

import be.c4j.ee.security.credentials.authentication.oauth2.application.ApplicationInfo;
import be.c4j.ee.security.shiro.OctopusUserFilter;
import org.apache.deltaspike.core.api.provider.BeanProvider;

/**
 *
 */
public class OAuth2UserFilter extends OctopusUserFilter {

    @Override
    public String getLoginUrl() {
        // FIXME Put these bean references at instance during the 'initialization'
        String result = "";
        ApplicationInfo applicationInfo = BeanProvider.getContextualReference(ApplicationInfo.class, true);
        if (applicationInfo != null) {
            result = '?' + OAuth2Configuration.APPLICATION + '=' + applicationInfo.getName();
        }
        OAuth2ServletInfo oAuth2ServletInfo = BeanProvider.getContextualReference(OAuth2ServletInfo.class);
        return oAuth2ServletInfo.getServletPath() + result;
    }
}
