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
package be.c4j.ee.security.credentials.authentication.oauth2;

import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.annotation.PostConstruct;
import javax.enterprise.context.SessionScoped;
import javax.faces.model.SelectItem;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 *
 */
@SessionScoped
public class DefaultOauth2ServletInfo implements OAuth2ServletInfo, Serializable {

    private List<OAuth2ProviderMetaData> providerInfos;

    // FIXME How are we going to set user selection
    private String userProviderSelection;

    private List<SelectItem> providerSelection;

    @PostConstruct
    public void init() {
        providerInfos = BeanProvider.getContextualReferences(OAuth2ProviderMetaData.class, false);

        providerSelection = new ArrayList<SelectItem>();
        for (OAuth2ProviderMetaData providerInfo : providerInfos) {
            providerSelection.add(new SelectItem(providerInfo.getName(), providerInfo.getName()));
        }

    }

    @Override
    public String getServletPath() {
        String result = null;
        if (userProviderSelection == null || userProviderSelection.isEmpty()) {
            // TODO what should happen if there are multiple.
            result = providerInfos.get(0).getServletPath();
        } else {
            Iterator<OAuth2ProviderMetaData> iter = providerInfos.iterator();
            while (result == null && iter.hasNext()) {
                OAuth2ProviderMetaData providerInfo = iter.next();
                if (providerInfo.getName().equals(userProviderSelection)) {
                    result = providerInfo.getServletPath();
                }
            }
        }
        return result;
    }

    public void setUserProviderSelection(String userProviderSelection) {
        this.userProviderSelection = userProviderSelection;
    }

    public List<SelectItem> getProviderSelection() {
        return providerSelection;
    }
}
