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

import javax.inject.Inject;
import javax.servlet.ServletException;
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

    private ThreadLocal<OpenIdVariableClientData> variableClientDataThreadLocal;

    private String loginURL;

    private String partialLoginURL; // Partial in the sense that the openIdConnect query parameters aren't present.

    @Inject
    private OctopusSSOClientConfiguration octopusSSOClientConfiguration;

    @Inject
    private URLUtil urlUtil;

    @Override
    public void init() throws ShiroException {
        BeanProvider.injectFields(this);

        variableClientDataThreadLocal = new ThreadLocal<OpenIdVariableClientData>();
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
    public void prepareLoginURL(ServletRequest request, ServletResponse response) {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;

        HttpSession session = httpServletRequest.getSession(true);

        if (session.getAttribute(OpenIdVariableClientData.class.getName()) == null) {
            // TODO when we integrate Shiro, We have to come up with a solution for this
            // Basically, it boils down to some initialization which is executed before the redirect to the login page is performed.
            // Maybe just an implementation of some interface which will be called.
            OpenIdVariableClientData variableClientData = new OpenIdVariableClientData(urlUtil.determineRoot((HttpServletRequest) request));
            variableClientDataThreadLocal.set(variableClientData);

            session.setAttribute(OpenIdVariableClientData.class.getName(), variableClientData);
        }
    }

    @Override
    protected void cleanup(ServletRequest request, ServletResponse response, Exception existing) throws ServletException, IOException {
        super.cleanup(request, response, existing);

        variableClientDataThreadLocal.remove();  // To be on the safe side that the ThreadLocal is cleanup properly.
        // TODO When shiro integrated we probably don't need this anymore as we don't use the ThreadLocal anymore.
    }

    @Override
    protected void redirectToLogin(ServletRequest req, ServletResponse res) throws IOException {
        determineActualLoginURL();
        super.redirectToLogin(req, res);
        loginURL = partialLoginURL;
    }

    private void determineActualLoginURL() {
        OpenIdVariableClientData variableClientData = variableClientDataThreadLocal.get();

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
