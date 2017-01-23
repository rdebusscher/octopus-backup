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
 *
 */
package be.c4j.ee.security.credentials.authentication.oauth2.filter;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2ProviderMetaData;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class OAuth2AuthcFilterManager {

    private List<OAuth2ProviderMetaData> oauth2ProviderMetaDataList;
    private Map<String, AbstractOAuth2AuthcFilter> filterForProvider;

    @PostConstruct
    public void init() {
        filterForProvider = new HashMap<String, AbstractOAuth2AuthcFilter>();
        oauth2ProviderMetaDataList = BeanProvider.getContextualReferences(OAuth2ProviderMetaData.class, false);
    }

    public void registerFilter(AbstractOAuth2AuthcFilter filter) {
        for (OAuth2ProviderMetaData metaData : oauth2ProviderMetaDataList) {
            if (metaData.getOAuth2AuthcFilter().equals(filter.getClass())) {
                filterForProvider.put(metaData.getName(), filter);
            }
        }
    }

    public AbstractOAuth2AuthcFilter getFilterForProvider(String provider) {
        return filterForProvider.get(provider);
    }
}
