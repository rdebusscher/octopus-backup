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
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

import javax.enterprise.context.ApplicationScoped;
import java.util.*;

/**
 *
 */
@ApplicationScoped
public class MemoryTokenStore implements SSOTokenStore {

    private Map<String, TokenStoreInfo> byAccessCode = new HashMap<String, TokenStoreInfo>();
    private Map<String, TokenStoreInfo> byCookieCode = new HashMap<String, TokenStoreInfo>();
    private Map<String, OIDCStoreData> byAuthorizationCode = new HashMap<String, OIDCStoreData>();

    @Override
    public OctopusSSOUser getUserByAccessCode(String accessCode) {
        OctopusSSOUser result = null;
        TokenStoreInfo tokenStoreInfo = byAccessCode.get(accessCode);
        if (tokenStoreInfo != null) {
            result = tokenStoreInfo.getOctopusSSOUser();
        }
        return result;

    }

    @Override
    public IDTokenClaimsSet getIdTokenByAccessCode(String accessCode) {
        TokenStoreInfo tokenStoreInfo = byAccessCode.get(accessCode);

        // FIXME Gives null pointer when user has already logged out
        return tokenStoreInfo.getOIDCStoreData().getIdTokenClaimsSet();
    }

    @Override
    public TokenStoreInfo getUserByCookieToken(String cookieToken) {
        return byCookieCode.get(cookieToken);
    }

    @Override
    public void removeUser(OctopusSSOUser octopusSSOUser) {
        byAccessCode.remove(octopusSSOUser.getAccessToken());
        for (Map.Entry<String, TokenStoreInfo> entry : byCookieCode.entrySet()) {
            if (entry.getValue().getOctopusSSOUser().equals(octopusSSOUser)) {
                byCookieCode.remove(entry.getKey());
            }
        }
    }

    @Override
    public void addLoginFromClient(OctopusSSOUser ssoUser, String cookieToken, String userAgent, String remoteHost, OIDCStoreData oidcStoreData) {

        TokenStoreInfo storeInfo = findStoreInfo(ssoUser);

        if (storeInfo == null) {
            // First logon
            storeInfo = new TokenStoreInfo(ssoUser, cookieToken, userAgent, remoteHost);

            byAccessCode.put(ssoUser.getAccessToken(), storeInfo);
            byCookieCode.put(cookieToken, storeInfo);
        }

        storeInfo.addOIDCStoreData(oidcStoreData);

        //oidcStoreData.setAccessCode(ssoUser.getBearerAccessToken());

        AuthorizationCode authorizationCode = oidcStoreData.getAuthorizationCode();
        if (authorizationCode != null) {
            byAuthorizationCode.put(authorizationCode.getValue(), oidcStoreData);
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
    public OIDCStoreData getOIDCDataByAuthorizationCode(AuthorizationCode authorizationCode) {
        return byAuthorizationCode.get(authorizationCode.getValue());
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
