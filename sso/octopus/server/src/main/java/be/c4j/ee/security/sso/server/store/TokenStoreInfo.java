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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 *
 */

public class TokenStoreInfo {


    private OctopusSSOUser octopusSSOUser;

    private Set<String> clientIds;
    private String cookieToken;

    private String userAgent;
    private String remoteHost;

    private List<OIDCStoreData> oidcStoreData;

    public TokenStoreInfo(OctopusSSOUser octopusSSOUser, String clientId, String cookieToken, String userAgent, String remoteHost) {
        this.octopusSSOUser = octopusSSOUser;
        clientIds = new HashSet<String>();
        clientIds.add(clientId);
        this.cookieToken = cookieToken;
        this.userAgent = userAgent;
        this.remoteHost = remoteHost;

        oidcStoreData = new ArrayList<OIDCStoreData>();
    }

    public OctopusSSOUser getOctopusSSOUser() {
        return octopusSSOUser;
    }

    public Set<String> getClientIds() {
        return clientIds;
    }

    public void addClientId(String clientId) {
        clientIds.add(clientId);
    }

    public void addOIDCStoreData(OIDCStoreData oidcStoreData) {
        this.oidcStoreData.add(oidcStoreData);
    }

    public OIDCStoreData getOIDCStoreData() {
        return oidcStoreData.get(0);  // TODO Verify but there should always be 1 there.
        // TODO Verify what happens if user logs out and afterwards a request comes in with the AccessCode
    }

    public String getCookieToken() {
        return cookieToken;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public String getRemoteHost() {
        return remoteHost;
    }

    @Override
    public String toString() {
        return "TokenStoreInfo{" +
                "octopusSSOUser=" + octopusSSOUser +
                ", clientIds=" + clientIdsLogValue() +
                ", cookieToken='" + cookieToken + '\'' +
                ", userAgent='" + userAgent + '\'' +
                ", remoteHost='" + remoteHost + '\'' +
                '}';
    }

    private String clientIdsLogValue() {

        StringBuilder result = new StringBuilder();
        for (String clientId : clientIds) {
            if (result.length() > 0) {
                result.append(", ");
            }
            result.append(clientId);
        }
        return result.toString();
    }
}
