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
package be.c4j.ee.security.credentials.authentication.oauth2.servlet;

import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.ee.security.credentials.authentication.oauth2.DefaultOauth2ServletInfo;
import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2ProviderMetaDataControl;
import be.c4j.ee.security.credentials.authentication.oauth2.fake.FakeCallbackHandler;
import com.github.scribejava.core.exceptions.OAuthException;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.authz.UnauthenticatedException;
import org.slf4j.Logger;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
@WebServlet(urlPatterns = {"/oauth2callback"})
public class OAuth2CallbackServlet extends HttpServlet {

    public static final String FAKE_MARKER = "Fake";

    @Inject
    protected Logger logger;

    @Inject
    private DefaultOauth2ServletInfo defaultOauth2ServletInfo;

    @Inject
    private OAuth2ProviderMetaDataControl oAuth2ProviderMetaDataControl;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        if (handleFakeLogin(request, response)) {
            return; // Fake login handled properly
        }

        OAuth2CallbackProcessor processor;
        if (defaultOauth2ServletInfo.getProviders().size() == 1) {
            processor = BeanProvider.getContextualReference(OAuth2CallbackProcessor.class);

        } else {
            String userProviderSelection = defaultOauth2ServletInfo.getUserProviderSelection();
            Class<? extends OAuth2CallbackProcessor> callbackProcessor = oAuth2ProviderMetaDataControl.getProviderMetaData(userProviderSelection).getCallbackProcessor();
            processor = BeanProvider.getContextualReference(callbackProcessor);
        }

        try {
            processor.processCallback(request, response);
        } catch (UnauthenticatedException exception) {
            OctopusJSFConfig config = BeanProvider.getContextualReference(OctopusJSFConfig.class);
            request.getRequestDispatcher(config.getUnauthorizedExceptionPage()).forward(request, response);
        } catch (OAuthException exception) {
            logger.warn(exception.getMessage());
            response.reset();
            response.setContentType("text/plain");
            response.getWriter().write("There was an issue processing the OAuth2 information.");
        }
    }

    private boolean handleFakeLogin(HttpServletRequest request, HttpServletResponse response) throws IOException {
        boolean result = false;
        // Document this functionality properly.
        if (request.getAttribute(FAKE_MARKER) != null) {
            result = true;

            FakeCallbackHandler callbackHandler = BeanProvider.getContextualReference(FakeCallbackHandler.class);
            callbackHandler.doAuthenticate(request, response);
        }
        return result;
    }
}