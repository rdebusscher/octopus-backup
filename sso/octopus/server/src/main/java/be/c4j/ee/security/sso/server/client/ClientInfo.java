/*
 * Copyright 2014-2018 Rudy De Busscher (www.c4j.be)
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

import be.c4j.ee.security.PublicAPI;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import com.nimbusds.jose.util.Base64;
import org.apache.shiro.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */
@PublicAPI
public class ClientInfo {

    private String callbackURL;
    private boolean multipleCallbackURL;
    private List<String> additionalCallbackURLs = new ArrayList<String>();  // TODO Verify if we return to the redirect_uri from the request or to the callbackURL.
    private boolean octopusClient;
    private boolean directAccessAllowed;
    private String idTokenSecret;  // For the idToken of the UserInfoEndpoint (signing of the JWT)
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
        this.callbackURL = processCallbackURL(callbackURL);
    }

    private String processCallbackURL(String callbackURL) {
        String result;
        URI uri;
        try {
            uri = new URI(callbackURL);
        } catch (URISyntaxException e) {
            // As we should have checked that it is a valid URL
            throw new OctopusUnexpectedException(e);
        }
        result = uri.normalize().toString();
        if (result.endsWith("/")) {
            result = result.substring(0, result.length() - 1);
        }
        return result;
    }

    public boolean hasMultipleCallbackURL() {
        return multipleCallbackURL;
    }

    public void additionalCallbackURL(String callbackURL) {
        // TODO We need some kind of builder so that we don't have the issue with setOctopusClient when this method is already called.
        if (!StringUtils.hasText(this.callbackURL)) {
            throw new ClientInfoCallbackException();
        }
        multipleCallbackURL = true;
        String url = processCallbackURL(callbackURL);

        if (octopusClient) {
            url = url + "/octopus/sso/SSOCallback";
        }

        additionalCallbackURLs.add(url);
    }

    public List<String> getAdditionalCallbackURLs() {
        return additionalCallbackURLs;
    }

    public boolean isOctopusClient() {
        return octopusClient;
    }

    public void setOctopusClient(boolean octopusClient) {
        if (!additionalCallbackURLs.isEmpty()) {
            // The additionalCallbackURL uses the octopusClient value, so we can't change it now.
            throw new ClientInfoOctopusClientException();
        }
        this.octopusClient = octopusClient;
    }

    public String getIdTokenSecret() {
        return idTokenSecret;
    }

    public byte[] getIdTokenSecretByte() {
        return new Base64(idTokenSecret).decode();
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

    public boolean isDirectAccessAllowed() {
        return directAccessAllowed;
    }

    public void setDirectAccessAllowed(boolean directAccessAllowed) {
        this.directAccessAllowed = directAccessAllowed;
    }
}
