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
package be.c4j.ee.security.sso.server.store;

import be.c4j.ee.security.sso.OctopusSSOUser;

import javax.enterprise.context.ApplicationScoped;
import java.util.*;

/**
 *
 */
@ApplicationScoped
public class MemoryTokenStore implements SSOTokenStore {

    private Map<String, OctopusSSOUser> byAccessCode = new HashMap<String, OctopusSSOUser>();
    private Map<String, TokenStoreInfo> byCookieCode = new HashMap<String, TokenStoreInfo>();


    @Override
    public void keepToken(TokenStoreInfo tokenStoreInfo) {
        OctopusSSOUser octopusSSOUser = tokenStoreInfo.getOctopusSSOUser();
        byAccessCode.put(octopusSSOUser.getToken(), octopusSSOUser);
        byCookieCode.put(tokenStoreInfo.getCookieToken(), tokenStoreInfo);
    }

    @Override
    public OctopusSSOUser getUserByAccessCode(String token) {
        return byAccessCode.get(token);

    }

    @Override
    public TokenStoreInfo getUserByCookieToken(String cookieToken) {
        return byCookieCode.get(cookieToken);
    }

    @Override
    public void removeUser(OctopusSSOUser octopusSSOUser) {
        byAccessCode.remove(octopusSSOUser.getToken());
        for (Map.Entry<String, TokenStoreInfo> entry : byCookieCode.entrySet()) {
            if (entry.getValue().getOctopusSSOUser().equals(octopusSSOUser)) {
                byCookieCode.remove(entry.getKey());
            }
        }
    }

    @Override
    public void addLoginFromClient(OctopusSSOUser ssoUser, String clientId) {
        TokenStoreInfo storeInfo = findStoreInfo(ssoUser);
        if (storeInfo != null) {
            // TODO We should always find an entry
            storeInfo.addClientId(clientId);
        }
    }

    private TokenStoreInfo findStoreInfo(OctopusSSOUser ssoUser) {
        TokenStoreInfo result = null;
        Iterator<Map.Entry<String, TokenStoreInfo>> iterator = byCookieCode.entrySet().iterator();
        while (result == null && iterator.hasNext()) {
            Map.Entry<String, TokenStoreInfo> entry = iterator.next();
            if (entry.getValue().getOctopusSSOUser().equals(ssoUser)) {
                result = entry.getValue();
            }
        }
        return result;
    }

    @Override
    public Set<String> getLoggedInClients(OctopusSSOUser octopusSSOUser) {
        Set<String> result = new HashSet<String>();
        TokenStoreInfo storeInfo = findStoreInfo(octopusSSOUser);
        if (storeInfo != null) {
            // TODO We should always find an entry
            result = storeInfo.getClientIds();
        }
        return result;
    }
}
