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
package be.c4j.ee.security.sso.server.token;

import be.c4j.ee.security.octopus.ProcessAuthenticationToken;
import be.c4j.ee.security.shiro.ValidatedAuthenticationToken;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.apache.shiro.authc.AuthenticationToken;

/**
 *
 */

public class OIDCEndpointToken implements ValidatedAuthenticationToken, ProcessAuthenticationToken, AuthenticationToken {


    private ClientAuthentication clientAuthentication;

    public OIDCEndpointToken(ClientAuthentication clientAuthentication) {
        this.clientAuthentication = clientAuthentication;
    }

    public ClientID getClientId() {
        return clientAuthentication.getClientID();
    }

    @Override
    public Object getPrincipal() {
        return getClientId();
    }

    @Override
    public Object getCredentials() {
        return null;
    }
}
