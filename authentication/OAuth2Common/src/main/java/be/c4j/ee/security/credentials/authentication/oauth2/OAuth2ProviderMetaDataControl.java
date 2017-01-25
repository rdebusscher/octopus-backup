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

import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class OAuth2ProviderMetaDataControl {

    private List<OAuth2ProviderMetaData> providerInfos;

    @PostConstruct
    public void init() {
        providerInfos = BeanProvider.getContextualReferences(OAuth2ProviderMetaData.class, false);
    }

    public List<OAuth2ProviderMetaData> getProviderInfos() {
        return providerInfos;
    }

    public OAuth2ProviderMetaData getProviderMetaData(String provider) {
        OAuth2ProviderMetaData result = null;
        for (OAuth2ProviderMetaData providerInfo : providerInfos) {
            if (providerInfo.getName().equals(provider)) {
                result = providerInfo;
            }
        }
        return result;
    }
}