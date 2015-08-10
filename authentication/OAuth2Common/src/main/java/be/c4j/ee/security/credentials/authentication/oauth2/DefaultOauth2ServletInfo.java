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