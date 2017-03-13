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
package be.c4j.ee.security.sso.server;

import be.c4j.ee.security.config.Debug;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.server.config.SSOServerConfiguration;
import be.c4j.ee.security.sso.server.cookie.SSOHelper;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;
import be.c4j.ee.security.sso.server.store.TokenStoreInfo;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.servlet.Cookie;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.UUID;

import static be.c4j.ee.security.realm.AuthenticationInfoBuilder.DEFAULT_REALM;


/**
 *
 */

public class SSOCookieRememberMeManager extends CookieRememberMeManager implements Initializable {

    private Logger logger = LoggerFactory.getLogger(SSOCookieRememberMeManager.class);

    private OctopusConfig octopusConfig;
    private SSOServerConfiguration ssoServerConfiguration;

    private SSOTokenStore tokenStore;

    private SSOHelper ssoHelper;

    @Override
    public void init() throws ShiroException {
        ssoServerConfiguration = BeanProvider.getContextualReference(SSOServerConfiguration.class);
        tokenStore = BeanProvider.getContextualReference(SSOTokenStore.class);
        ssoHelper = BeanProvider.getContextualReference(SSOHelper.class);

        createTemplateCookie();
    }

    private void createTemplateCookie() {

        Cookie cookie = new SimpleCookie(getCookie()); // Use Shiro default
        // Now change values for ours Defaults
        cookie.setName(ssoServerConfiguration.getSSOCookieName());
        cookie.setComment("Octopus SSO token");

        cookie.setSecure(Boolean.valueOf(ssoServerConfiguration.getSSOCookieSecure()));

        cookie.setMaxAge(ssoServerConfiguration.getSSOCookieTimeToLive() * 60 * 60); // Hours -> Seconds

        setCookie(cookie);

    }

    @Override
    public void onSuccessfulLogin(Subject subject, AuthenticationToken token, AuthenticationInfo info) {
        String clientId = ssoHelper.getSSOClientId(subject);
        if (clientId != null && !clientId.trim().isEmpty()) {
            rememberIdentity(subject, token, info);
        } else {
            super.onSuccessfulLogin(subject, token, info);
        }
    }

    @Override
    protected void rememberIdentity(Subject subject, PrincipalCollection accountPrincipals) {

        OctopusSSOUser ssoUser = accountPrincipals.oneByType(OctopusSSOUser.class);
        if (ssoUser != null) {

            // FIXME Don't create a new Cookie token when authenticated from the cookie
            String cookieToken = UUID.randomUUID().toString();
            ssoUser.setCookieToken(cookieToken);

            byte[] bytes;
            if (getCipherService() != null) {
                bytes = getCipherService().encrypt(cookieToken.getBytes(), getDecryptionCipherKey()).getBytes();
            } else {
                bytes = cookieToken.getBytes();
            }

            rememberSerializedIdentity(subject, bytes);
        }

    }

    public PrincipalCollection getRememberedPrincipals(SubjectContext subjectContext) {
        PrincipalCollection principals = null;

        HttpServletRequest httpRequest = WebUtils.getHttpRequest(subjectContext);
        if (!WebUtils.getRequestUri(httpRequest).contains("/octopus/")) {
            // We are logging into the SSO server itself, not a client application.
            // Never use the SSO cookies for the main app itself.
            return null;
        }

        try {
            byte[] bytes = getRememberedSerializedIdentity(subjectContext);
            //SHIRO-138 - only call convertBytesToPrincipals if bytes exist:
            if (bytes != null && bytes.length > 0) {

                String cookieToken;
                if (getCipherService() != null) {
                    cookieToken = new String(getCipherService().decrypt(bytes, getDecryptionCipherKey()).getBytes());
                } else {
                    cookieToken = new String(bytes);
                }

                OctopusSSOUser ssoUser = retrieveUserFromCookieToken(cookieToken, httpRequest);

                if (ssoUser != null) {
                    showDebugInfo(ssoUser);

                    principals = new SimplePrincipalCollection(ssoUser, DEFAULT_REALM);
                }
            }
        } catch (RuntimeException re) {
            principals = onRememberedPrincipalFailure(re, subjectContext);
        }

        return principals;
    }

    public OctopusSSOUser retrieveUserFromCookieToken(String realToken, HttpServletRequest request) {
        OctopusSSOUser user = null;
        TokenStoreInfo cookieInfo = tokenStore.getUserByCookieToken(realToken);

        boolean result = verifyCookieInformation(cookieInfo, request);

        if (result) {
            user = cookieInfo.getOctopusSSOUser();
        }

        return user;
    }

    private boolean verifyCookieInformation(TokenStoreInfo cookieInfo, HttpServletRequest request) {
        boolean result = cookieInfo != null;
        if (result) {
            String remoteHost = request.getRemoteAddr();

            result = remoteHost.equals(cookieInfo.getRemoteHost());
        }
        if (result) {
            String userAgent = request.getHeader("User-Agent");

            result = userAgent.equals(cookieInfo.getUserAgent());
        }
        return result;
    }

    private void showDebugInfo(OctopusSSOUser user) {
        if (octopusConfig == null) {
            octopusConfig = BeanProvider.getContextualReference(OctopusConfig.class);
        }

        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("User %s is authenticated from SSO Cookie %s", user.getFullName(), user.getAccessToken()));
        }
    }


}
