package be.c4j.ee.security.credentials.authentication.oauth2.info;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.event.LogonEvent;
import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.authc.AuthenticationInfo;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class ExternalInternalIdMapper {

    private Map<String, Serializable> idMap;

    @PostConstruct
    public void init() {
        idMap = new HashMap<String, Serializable>();
    }

    public void onLogon(@Observes LogonEvent logonEvent) {
        UserPrincipal userPrincipal = (UserPrincipal) logonEvent.getInfo().getPrincipals().getPrimaryPrincipal();
        idMap.put(userPrincipal.getId().toString(), userPrincipal.getInfo().get(OAuth2User.LOCAL_ID));
    }

    public String getLocalId(String id) {
        String result = null;
        Serializable value = idMap.get(id);
        if (value != null) {
            result = value.toString();
        }
        return result;
    }
}
