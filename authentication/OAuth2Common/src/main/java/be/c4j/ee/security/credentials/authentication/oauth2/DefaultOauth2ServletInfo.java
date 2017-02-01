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

import be.c4j.ee.security.exception.OctopusUnexpectedException;
import org.apache.shiro.web.util.SavedRequest;
import org.apache.shiro.web.util.WebUtils;

import javax.annotation.PostConstruct;
import javax.enterprise.context.SessionScoped;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.ServletRequest;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 *
 */
@SessionScoped
@Named
public class DefaultOauth2ServletInfo implements OAuth2ServletInfo, Serializable {

    @Inject
    private OAuth2Configuration oAuth2Configuration;

    @Inject
    private OAuth2ProviderMetaDataControl oAuth2ProviderMetaDataControl;

    private String userProviderSelection;

    private List<SelectItem> providerSelection;
    private List<OAuth2ProviderMetaData> providerInfos;

    @PostConstruct
    public void init() {

        providerInfos = oAuth2ProviderMetaDataControl.getProviderInfos();

        providerSelection = new ArrayList<SelectItem>();
        for (OAuth2ProviderMetaData providerInfo : providerInfos) {
            providerSelection.add(new SelectItem(providerInfo.getName(), providerInfo.getName()));
        }

    }

    @Override
    public String getServletPath() {
        String result = null;
        if (userProviderSelection == null || userProviderSelection.isEmpty()) {
            if (providerInfos.size() > 1) {
                result = oAuth2Configuration.getOAuth2ProviderSelectionPage();
            } else {
                result = providerInfos.get(0).getServletPath();
            }
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

    public void authenticateWith(String userProviderSelection) {
        this.userProviderSelection = userProviderSelection;
        ExternalContext externalContext = FacesContext.getCurrentInstance().getExternalContext();
        SavedRequest savedRequest = WebUtils
                .getAndClearSavedRequest((ServletRequest) externalContext
                        .getRequest());

        try {
            externalContext
                    .redirect(savedRequest != null ? savedRequest.getRequestUrl() : getRootUrl(externalContext));
        } catch (IOException e) {
            throw new OctopusUnexpectedException(e);
        }

    }

    private String getRootUrl(ExternalContext externalContext) {
        return externalContext.getRequestContextPath();
    }

    public String getUserProviderSelection() {
        return userProviderSelection;
    }

    public List<SelectItem> getProviderSelectItems() {
        return providerSelection;
    }

    public List<String> getProviders() {
        List<String> result = new ArrayList<String>();
        for (SelectItem selectItem : providerSelection) {
            result.add(selectItem.getLabel());
        }
        return result;
    }
}
