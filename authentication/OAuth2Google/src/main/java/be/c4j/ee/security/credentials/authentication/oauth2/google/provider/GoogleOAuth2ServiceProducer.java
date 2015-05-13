/*
 * Copyright 2014-2015 Rudy De Busscher (www.c4j.be)
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
 *
 */
package be.c4j.ee.security.credentials.authentication.oauth2.google.provider;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2Configuration;
import be.c4j.ee.security.credentials.authentication.oauth2.google.scribe.Google2Api;
import org.scribe.builder.ServiceBuilder;
import org.scribe.oauth.OAuthService;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
@ApplicationScoped
public class GoogleOAuth2ServiceProducer {

    @Inject
    private OAuth2Configuration configuration;

    public OAuthService createOAuthService(HttpServletRequest req) {
        //Configure
        ServiceBuilder builder = new ServiceBuilder();
        OAuthService service = builder.provider(Google2Api.class)
                .apiKey(configuration.getClientId())
                .apiSecret(configuration.getClientSecret())
                .callback(assembleCallbackUrl(req))
                .scope("openid profile email " +
                        "https://www.googleapis.com/auth/plus.login " +
                        "https://www.googleapis.com/auth/plus.me")
                .debug()
                .build(); //Now build the call

        return service;
    }

    private String assembleCallbackUrl(HttpServletRequest req) {
        StringBuilder result = new StringBuilder();
        result.append(req.getScheme()).append("://");
        result.append(req.getServerName()).append(':');
        result.append(req.getServerPort());
        result.append(req.getContextPath()).append("/oauth2callback");
        return result.toString();
    }
}
