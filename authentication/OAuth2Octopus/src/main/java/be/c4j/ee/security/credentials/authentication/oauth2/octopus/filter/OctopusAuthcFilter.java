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
package be.c4j.ee.security.credentials.authentication.oauth2.octopus.filter;

import be.c4j.ee.security.credentials.authentication.oauth2.filter.AbstractOAuth2AuthcFilter;
import be.c4j.ee.security.credentials.authentication.oauth2.info.OAuth2InfoProvider;
import be.c4j.ee.security.credentials.authentication.oauth2.octopus.OctopusProviderLiteral;
import be.rubus.web.jerry.provider.BeanProvider;

/**
 *
 */
public class OctopusAuthcFilter extends AbstractOAuth2AuthcFilter {

    private OAuth2InfoProvider infoProvider;

    public OctopusAuthcFilter() {
        setAuthcScheme("Octopus OAuth2");
    }

    @Override
    public void init() {
        super.init();
        infoProvider = BeanProvider.getContextualReference(OAuth2InfoProvider.class, false, new OctopusProviderLiteral());
    }

    @Override
    protected OAuth2InfoProvider getInfoProvider() {
        return infoProvider;
    }
}
