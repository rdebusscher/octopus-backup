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
import com.nimbusds.oauth2.sdk.id.ClientID;

import javax.enterprise.context.ApplicationScoped;
import java.util.*;

/**
 *
 */
@ApplicationScoped
public class MemoryTokenStore implements SSOTokenStore {

    // FIXME Need background job to remove old expired tokens
    private Map<String, TokenStoreInfo> byAccessCode = new HashMap<String, TokenStoreInfo>();
    private Map<String, TokenStoreInfo> byCookieCode = new HashMap<String, TokenStoreInfo>();
    private Map<String, OIDCStoreData> byAuthorizationCode = new HashMap<String, OIDCStoreData>();

    @Override
    public OctopusSSOUser getUserByAccessCode(String accessCode) {
        OctopusSSOUser result = null;
        TokenStoreInfo tokenStoreInfo = byAccessCode.get(accessCode);
        if (tokenStoreInfo != null) {
            OIDCStoreData oidcStoreData = tokenStoreInfo.findOIDCStoreData(accessCode);

            if (oidcStoreData.getExpiresOn().before(new Date())) {
                // Using expired Access Token
                byAccessCode.remove(accessCode);
            } else {
                result = tokenStoreInfo.getOctopusSSOUser();
            }
        }
        return result;

    }

    @Override
    public OIDCStoreData getOIDCDataByAccessToken(String accessCode) {
        OIDCStoreData result = null;
        TokenStoreInfo tokenStoreInfo = byAccessCode.get(accessCode);

        if (tokenStoreInfo != null) {
            OIDCStoreData oidcStoreData = tokenStoreInfo.findOIDCStoreData(accessCode);

            if (oidcStoreData.getExpiresOn().before(new Date())) {
                // Using expired Access Token
                byAccessCode.remove(accessCode);
            } else {
                result = oidcStoreData;
            }
        }
        return result;
    }

    @Override
    public TokenStoreInfo getUserByCookieToken(String cookieToken) {
        return byCookieCode.get(cookieToken);
    }

    @Override
    public void removeUser(OctopusSSOUser octopusSSOUser) {
        // Remove entries by AccessToken
        Map.Entry<String, TokenStoreInfo> entry;
        Iterator<Map.Entry<String, TokenStoreInfo>> iterator = byAccessCode.entrySet().iterator();
        while (iterator.hasNext()) {
            entry = iterator.next();
            if (entry.getValue().getOctopusSSOUser().equals(octopusSSOUser)) {
                iterator.remove();
            }

        }

        // Remove entries by Cookie
        iterator = byCookieCode.entrySet().iterator();
        while (iterator.hasNext()) {
            entry = iterator.next();
            if (entry.getValue().getOctopusSSOUser().equals(octopusSSOUser)) {
                byCookieCode.remove(entry.getKey());
            }
        }

        // Remove by AuthorizationCode (should be empty as Authorization codes are removed when used.
        // TODO
    }

    @Override
    public void addLoginFromClient(OctopusSSOUser ssoUser, String cookieToken, String userAgent, String remoteHost, OIDCStoreData oidcStoreData) {

        TokenStoreInfo storeInfo;
        if (cookieToken != null) {
            storeInfo = findStoreInfoByCookieToken(ssoUser);
        } else {
            storeInfo = findStoreInfoByAccessToken(ssoUser);
        }

        if (storeInfo == null) {
            // First logon
            storeInfo = new TokenStoreInfo(ssoUser, cookieToken, userAgent, remoteHost);

            if (cookieToken != null) {
                byCookieCode.put(cookieToken, storeInfo);
            }
        }

        storeInfo.addOIDCStoreData(oidcStoreData);
        byAccessCode.put(oidcStoreData.getAccessToken().getValue(), storeInfo);

        AuthorizationCode authorizationCode = oidcStoreData.getAuthorizationCode();
        if (authorizationCode != null) {
            byAuthorizationCode.put(authorizationCode.getValue(), oidcStoreData);
        }

    }

    private TokenStoreInfo findStoreInfoByCookieToken(OctopusSSOUser ssoUser) {
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

    private TokenStoreInfo findStoreInfoByAccessToken(OctopusSSOUser ssoUser) {
        TokenStoreInfo result = null;
        Iterator<Map.Entry<String, TokenStoreInfo>> iterator = byAccessCode.entrySet().iterator();
        while (result == null && iterator.hasNext()) {
            Map.Entry<String, TokenStoreInfo> entry = iterator.next();
            if (entry.getValue().getOctopusSSOUser().equals(ssoUser)) {
                result = entry.getValue();
            }
        }
        return result;
    }

    @Override
    public OIDCStoreData getOIDCDataByAuthorizationCode(AuthorizationCode authorizationCode, ClientID clientId) {
        OIDCStoreData result = byAuthorizationCode.get(authorizationCode.getValue());
        if (result != null && result.getClientId().equals(clientId)) {
            // TODO Don't we have a time aspect on the authorization code?
            byAuthorizationCode.remove(authorizationCode.getValue()); // Make sure that the authorizationCode is only used once.
        } else {
            result = null; // ClientId doesn't match,
        }
        return result;
    }

    @Override
    public List<OIDCStoreData> getLoggedInClients(OctopusSSOUser octopusSSOUser) {
        List<OIDCStoreData> result = new ArrayList<OIDCStoreData>();
        TokenStoreInfo storeInfo = findStoreInfoByCookieToken(octopusSSOUser);
        if (storeInfo != null) {
            // TODO We should always find an entry
            result.addAll(storeInfo.getOidcStoreData());
        }
        return result;
    }
}
