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

import java.util.Set;

/**
 *
 */
public interface SSOTokenStore {

    void keepToken(TokenStoreInfo tokenStoreInfo);

    OctopusSSOUser getUserByAccessCode(String accessCode);

    IDTokenClaimsSet getIdTokenByAccessCode(String accessCode);

    OIDCStoreData getOIDCDataByAuthorizationCode(AuthorizationCode authorizationCode);

    TokenStoreInfo getUserByCookieToken(String cookieToken);

    void removeUser(OctopusSSOUser octopusSSOUser);

    void addLoginFromClient(OctopusSSOUser ssoUser, String clientId, OIDCStoreData oidcStoreData);

    Set<String> getLoggedInClients(OctopusSSOUser octopusSSOUser);
}
