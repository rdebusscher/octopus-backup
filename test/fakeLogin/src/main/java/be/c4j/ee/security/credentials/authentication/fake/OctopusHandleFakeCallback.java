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
package be.c4j.ee.security.credentials.authentication.fake;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2Configuration;
import be.c4j.ee.security.credentials.authentication.oauth2.application.CustomCallbackProvider;
import be.c4j.ee.security.credentials.authentication.oauth2.fake.FakeCallbackHandler;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.slf4j.Logger;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
@ApplicationScoped
public class OctopusHandleFakeCallback implements FakeCallbackHandler {

    @Inject
    private Logger logger;

    private CustomCallbackProvider customCallbackProvider;

    @Inject
    private OAuth2TokenStore tokenStore;

    @PostConstruct
    public void init() {
        customCallbackProvider = BeanProvider.getContextualReference(CustomCallbackProvider.class, true);

    }

    public void doAuthenticate(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // We have come this far, the CustomCallbackProvider implementation is required
        if (customCallbackProvider == null) {
            throw new OctopusConfigurationException("Missing implementation for CustomCallbackProvider");
        }
        String applicationName = request.getParameter(OAuth2Configuration.APPLICATION);

        if (customCallbackProvider != null) {
            String callbackURL = customCallbackProvider.determineApplicationCallbackURL(applicationName);

            String userParameter = request.getParameter("user");
            response.sendRedirect(callbackURL + "?token=" + tokenStore.retrieveToken(userParameter));
        } else {
            logger.warn("Fake login could not be completes as there is no CDI instance for CustomCallbackProvider found");
        }
    }
}
