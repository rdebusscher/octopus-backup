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
import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2SessionAttributes;
import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.credentials.authentication.oauth2.info.OAuth2InfoProvider;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.session.SessionUtil;
import com.github.scribejava.core.exceptions.OAuthException;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.web.util.SavedRequest;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

/**
 *
 */
public abstract class OAuth2CallbackProcessor {

    @Inject
    protected Logger logger;

    @Inject
    private OctopusJSFConfig octopusConfig;

    @Inject
    private SessionUtil sessionUtil;

    @Inject
    private OAuth2SessionAttributes oAuth2SessionAttributes;

    public abstract void processCallback(HttpServletRequest request, HttpServletResponse response) throws IOException;

    protected boolean checkCSRFToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        boolean result = true;
        String csrfToken = oAuth2SessionAttributes.getCSRFToken(request);
        String state = request.getParameter("state");
        if (csrfToken == null || !csrfToken.equals(state)) {
            logger.warn(String.format("The CSRF token does not match (session %s - request %s)", csrfToken, state));
            // The CSRF token do not match, deny access.
            HttpSession sess = request.getSession();
            sess.invalidate();
            response.sendRedirect(request.getContextPath());
            result = false;
        }
        return result;

    }

    protected void doAuthenticate(HttpServletRequest request, HttpServletResponse response, OAuth2InfoProvider infoProvider) throws IOException {
        OAuth20Service service = oAuth2SessionAttributes.getOAuth2Service(request);

        //Get the all important authorization code
        String code = request.getParameter(getAccessTokenParameterName());
        //Construct the access token
        OAuth2AccessToken token;
        try {
            token = service.getAccessToken(code);
        } catch (InterruptedException e) {
            throw new OctopusUnexpectedException(e);
        } catch (ExecutionException e) {
            throw new OctopusUnexpectedException(e);
        }

        OAuth2User oAuth2User = infoProvider.retrieveUserInfo(token, request);

        // It is possible that the infoProvider can't retrieve the information. So handle this here
        if (oAuth2User == null) {
            throw new OAuthException("Failed to retrieve information from the OAuth2 Authentication token");
        }

        try {

            SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(request);
            sessionUtil.invalidateCurrentSession(request);

            SecurityUtils.getSubject().login(oAuth2User);
            response.sendRedirect(savedRequest != null ? savedRequest.getRequestUrl() : request.getContextPath());
        } catch (AuthenticationException e) {
            HttpSession sess = request.getSession();
            sess.setAttribute(OAuth2User.OAUTH2_USER_INFO, oAuth2User);
            sess.setAttribute("AuthenticationExceptionMessage", e.getMessage());
            // DataSecurityProvider decided that google user has no access to application
            response.sendRedirect(request.getContextPath() + octopusConfig.getUnauthorizedExceptionPage());
        }

    }

    protected String getAccessTokenParameterName() {
        return "code";
    }

}
