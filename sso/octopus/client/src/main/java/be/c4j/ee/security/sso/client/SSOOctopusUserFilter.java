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
package be.c4j.ee.security.sso.client;

import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.shiro.OctopusUserFilter;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import be.c4j.ee.security.util.URLUtil;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.ShiroException;
import org.apache.shiro.util.Initializable;
import org.slf4j.Logger;

import javax.inject.Inject;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 *
 */
public class SSOOctopusUserFilter extends OctopusUserFilter implements Initializable {

    @Inject
    private Logger logger;

    private String loginURL;

    private String partialLoginURL; // Partial in the sense that the openIdConnect query parameters aren't present.

    @Inject
    private OctopusSSOClientConfiguration octopusSSOClientConfiguration;

    @Inject
    private URLUtil urlUtil;

    private ClientCallbackHelper clientCallbackHelper;

    @Override
    public void init() throws ShiroException {
        BeanProvider.injectFields(this);
        clientCallbackHelper = BeanProvider.getContextualReference(ClientCallbackHelper.class, true);
    }

    @Override
    public String getLoginUrl() {
        if (loginURL == null) {
            partialLoginURL = super.getLoginUrl();
            loginURL = partialLoginURL;
        }
        return loginURL;
    }

    @Override
    protected void redirectToLogin(ServletRequest req, ServletResponse res) throws IOException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) req;
        String rootURL;
        if (clientCallbackHelper == null) {
            rootURL = urlUtil.determineRoot(httpServletRequest);
        } else {
            rootURL = clientCallbackHelper.determineCallbackRoot(httpServletRequest);
        }

        OpenIdVariableClientData variableClientData = new OpenIdVariableClientData(rootURL);

        determineActualLoginURL(variableClientData);
        storeClientData(httpServletRequest, variableClientData);

        super.redirectToLogin(req, res);
        loginURL = partialLoginURL;
    }

    private void storeClientData(HttpServletRequest request, OpenIdVariableClientData variableClientData) {
        HttpSession session = request.getSession(true);

        if (session.getAttribute(OpenIdVariableClientData.class.getName()) != null) {
            logger.warn("State and Nonce value for OpenIdConnect already present within session");
        }
        // TODO The idea was that within a session, there could be only 1 logon attempt.
        // But there where some issue reported in more complex situations so this check is disabled for the moment.
        // The above warning is added as compensation so that there is a trace how many times it happen.
        //if (session.getAttribute(OpenIdVariableClientData.class.getName()) == null) {

            session.setAttribute(OpenIdVariableClientData.class.getName(), variableClientData);
        //}
    }

    private void determineActualLoginURL(OpenIdVariableClientData variableClientData) {

        AuthenticationRequest req;
        try {
            URI callback = new URI(variableClientData.getRootURL() + "/octopus/sso/SSOCallback");
            ClientID clientId = new ClientID(octopusSSOClientConfiguration.getSSOClientId());
            req = new AuthenticationRequest(
                    new URI(partialLoginURL),
                    octopusSSOClientConfiguration.getSSOType().getResponseType(),
                    Scope.parse("openid octopus " + octopusSSOClientConfiguration.getSSOScopes()),
                    clientId,
                    callback,
                    variableClientData.getState(),
                    variableClientData.getNonce());
        } catch (URISyntaxException e) {
            throw new OctopusUnexpectedException(e);
        }

        loginURL = partialLoginURL + '?' + req.toHTTPRequest().getQuery();

    }
}
