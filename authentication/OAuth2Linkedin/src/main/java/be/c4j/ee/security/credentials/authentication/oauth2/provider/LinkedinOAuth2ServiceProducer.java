/*
 * Copyright 2014-2016 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.credentials.authentication.oauth2.provider;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2Configuration;
import com.github.scribejava.apis.GitHubApi;
import com.github.scribejava.apis.LinkedInApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.oauth.OAuth20Service;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
@ApplicationScoped
public class LinkedinOAuth2ServiceProducer extends OAuth2ServiceProducer {

    @Inject
    private OAuth2Configuration configuration;

    /**
     * @param req
     * @param csrfToken value for the state parameter, allowed to be null in case you don't need it
     * @return
     */
    @Override
    public OAuth20Service createOAuthService(HttpServletRequest req, String csrfToken) {
        //Configure
        ServiceBuilder builder = new ServiceBuilder();
        ServiceBuilder serviceBuilder = builder
                .apiKey(configuration.getClientId())
                .apiSecret(configuration.getClientSecret())
                .callback(assembleCallbackUrl(req))
                .scope("r_basicprofile r_emailaddress " + configuration.getOAuth2Scopes())
                .debug();
        // No scopes needed, as we just need to have read access to public information.

        if (csrfToken != null && !csrfToken.isEmpty()) {
            serviceBuilder.state(csrfToken);
        }

        return serviceBuilder.build(LinkedInApi20.instance());
    }

}
