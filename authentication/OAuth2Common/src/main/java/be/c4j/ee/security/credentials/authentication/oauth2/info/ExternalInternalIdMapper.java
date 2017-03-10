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
package be.c4j.ee.security.credentials.authentication.oauth2.info;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.event.LogonEvent;
import be.c4j.ee.security.model.UserPrincipal;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class ExternalInternalIdMapper {

    private Map<String, Object> idMap;

    @PostConstruct
    public void init() {
        idMap = new HashMap<String, Object>();
    }

    public void onLogon(@Observes LogonEvent logonEvent) {
        Object primaryPrincipal = logonEvent.getInfo().getPrincipals().getPrimaryPrincipal();
        if (primaryPrincipal instanceof UserPrincipal) {
            UserPrincipal userPrincipal = (UserPrincipal) primaryPrincipal;
            idMap.put(userPrincipal.getId().toString(), userPrincipal.getInfo().get(OAuth2User.LOCAL_ID));
        }
    }

    public String getLocalId(String id) {
        String result = null;
        Object value = idMap.get(id);
        if (value != null) {
            result = value.toString();
        }
        return result;
    }
}
