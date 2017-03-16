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
package be.c4j.ee.security.sso.server.client;

import be.c4j.ee.security.exception.OctopusUnexpectedException;
import com.nimbusds.jose.util.Base64;

import java.net.URI;
import java.net.URISyntaxException;

/**
 *
 */
public class ClientInfo {

    private String callbackURL;
    private boolean octopusClient;
    private String idTokenSecret;  // FIXME Convert to byte !!
    private String clientSecret;  // For the ClientAuthentication of the TokenEndpoint (signing of the JWT)

    public String getCallbackURL() {
        return callbackURL;
    }

    public String getActualCallbackURL() {
        if (octopusClient) {
            return callbackURL + "/octopus/sso/SSOCallback";
        } else {
            return callbackURL;
        }
    }

    public void setCallbackURL(String callbackURL) {
        URI uri;
        try {
            uri = new URI(callbackURL);
        } catch (URISyntaxException e) {
            // As we should have checked that it is a valid URL
            throw new OctopusUnexpectedException(e);
        }
        this.callbackURL = uri.normalize().toString();
        if (this.callbackURL.endsWith("/")) {
            this.callbackURL = this.callbackURL.substring(0, this.callbackURL.length() - 1);
        }
    }

    public boolean isOctopusClient() {
        return octopusClient;
    }

    public void setOctopusClient(boolean octopusClient) {
        this.octopusClient = octopusClient;
    }

    public String getIdTokenSecret() {
        return idTokenSecret;
    }

    public void setIdTokenSecret(String idTokenSecret) {
        this.idTokenSecret = idTokenSecret;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public byte[] getClientSecretByte() {
        return new Base64(clientSecret).decode();
    }


    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }
}
