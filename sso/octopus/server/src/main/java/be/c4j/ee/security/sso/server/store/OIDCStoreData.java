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

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

/**
 *
 */

public class OIDCStoreData {

    private ClientID clientId;
    private Scope scope;

    private AuthorizationCode authorizationCode;
    private BearerAccessToken accessCode;
    private IDTokenClaimsSet idTokenClaimsSet;

    public ClientID getClientId() {
        return clientId;
    }

    public void setClientId(ClientID clientId) {
        this.clientId = clientId;
    }

    public Scope getScope() {
        return scope;
    }

    public void setScope(Scope scope) {
        this.scope = scope;
    }

    public AuthorizationCode getAuthorizationCode() {
        return authorizationCode;
    }

    public void setAuthorizationCode(AuthorizationCode authorizationCode) {
        this.authorizationCode = authorizationCode;
    }

    public BearerAccessToken getAccessCode() {
        return accessCode;
    }

    public void setAccessCode(BearerAccessToken accessCode) {
        this.accessCode = accessCode;
    }

    public IDTokenClaimsSet getIdTokenClaimsSet() {
        return idTokenClaimsSet;
    }

    public void setIdTokenClaimsSet(IDTokenClaimsSet idTokenClaimsSet) {
        this.idTokenClaimsSet = idTokenClaimsSet;
    }
}
