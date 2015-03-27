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
package be.c4j.ee.security.credentials.authentication.oauth2.google.filter;

import be.c4j.ee.security.credentials.authentication.oauth2.google.GoogleUser;
import be.c4j.ee.security.credentials.authentication.oauth2.google.application.ApplicationInfo;
import be.c4j.ee.security.credentials.authentication.oauth2.google.json.GoogleJSONProcessor;
import be.c4j.ee.security.credentials.authentication.oauth2.google.provider.GoogleOAuth2ServiceProducer;
import be.c4j.ee.security.fake.LoginAuthenticationTokenProvider;
import be.rubus.web.jerry.provider.BeanProvider;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.mgt.CachingSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.oauth.OAuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;

/**
 *
 */
public class GoogleAuthcFilter extends BasicHttpAuthenticationFilter {

    private GoogleOAuth2ServiceProducer googleOAuth2ServiceProducer;

    private GoogleJSONProcessor jsonProcessor;

    private LoginAuthenticationTokenProvider loginAuthenticationTokenProvider;

    /**
     * This class's private logger.
     */
    private static final Logger log = LoggerFactory.getLogger(BasicHttpAuthenticationFilter.class);

    public GoogleAuthcFilter() {
        setAuthcScheme("Google OAuth2");
        setAuthzScheme("Bearer");
        googleOAuth2ServiceProducer = BeanProvider.getContextualReference(GoogleOAuth2ServiceProducer.class, false);
        jsonProcessor = BeanProvider.getContextualReference(GoogleJSONProcessor.class, false);
        loginAuthenticationTokenProvider = BeanProvider.getContextualReference(LoginAuthenticationTokenProvider.class, true);
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
        String authorizationHeader = getAuthzHeader(request);
        if (authorizationHeader == null || authorizationHeader.length() == 0) {
            // Create an empty authentication token since there is no
            // Authorization header.
            return createToken("", "", request, response);
        }

        if (log.isDebugEnabled()) {
            log.debug("Attempting to execute login with headers [" + authorizationHeader + "]");
        }

        String[] authTokens = authorizationHeader.split(" ");
        if (authTokens.length < 2) {
            return null;
        }

        String authToken = authTokens[1];
        GoogleUser googleUser = getCachedGoogleUser(authToken);

        if (googleUser == null) {
            googleUser = useFakeLogin(request, authToken);
        }

        if (googleUser == null) {
            // We don't have a cached version which is still valid.
            googleUser = getGoogleUser(request, authToken);

            if (googleUser != null) {
                googleUser.setToken(new Token(authToken, ""));
                setCachedGoogleUser(authToken, googleUser);
            }
        }

        if (googleUser == null) {
            ((HttpServletResponse) response).setStatus(401);
            return new DummyGoogleAuthenticationToken();
        }

        setApplication(googleUser);
        return googleUser;
    }

    private void setApplication(GoogleUser googleUser) {
        ApplicationInfo applicationInfo = BeanProvider.getContextualReference(ApplicationInfo.class, true);
        if (applicationInfo != null) {
            googleUser.setApplicationName(applicationInfo.getName());
        }

    }

    private GoogleUser useFakeLogin(ServletRequest request, String authToken) {
        GoogleUser result = null;
        if ("localhost".equals(request.getServerName()) && loginAuthenticationTokenProvider != null) {
            result = (GoogleUser) loginAuthenticationTokenProvider.determineAuthenticationToken(authToken);
        }
        return result;
    }

    private void setCachedGoogleUser(String authToken, GoogleUser googleUser) {
        Cache<String, CachedGoogleUser> cache = getCache();

        if (cache != null) {
            cache.put(authToken, new CachedGoogleUser(googleUser));
        }
    }

    private GoogleUser getGoogleUser(ServletRequest request, String authToken) {
        OAuthService authService = googleOAuth2ServiceProducer.createOAuthService(WebUtils.toHttp(request));

        Token token = new Token(authToken, "");

        OAuthRequest oReq = new OAuthRequest(Verb.GET, "https://www.googleapis.com/oauth2/v2/userinfo");

        authService.signRequest(token, oReq);
        Response oResp = oReq.send();
        return jsonProcessor.extractGoogleUser(oResp.getBody());
    }

    private GoogleUser getCachedGoogleUser(String authToken) {
        GoogleUser result = null;
        Cache<String, CachedGoogleUser> cache = getCache();

        if (cache != null) {
            CachedGoogleUser cachedGoogleUser = cache.get(authToken);
            if (cachedGoogleUser != null && cachedGoogleUser.isNotTimedOut()) {
                result = cachedGoogleUser.getGoogleUser();
            }
        }
        return result;
    }

    private Cache<String, CachedGoogleUser> getCache() {
        Cache<String, CachedGoogleUser> cache = null;
        SecurityManager securityManager = SecurityUtils.getSecurityManager();
        if (securityManager instanceof CachingSecurityManager) {
            CachingSecurityManager cachingSecurityManager = (CachingSecurityManager) securityManager;
            cache = cachingSecurityManager.getCacheManager().getCache("AuthenticationToken");


        }
        return cache;
    }


    public static class DummyGoogleAuthenticationToken implements AuthenticationToken {

        @Override
        public Object getPrincipal() {
            return null;
        }

        @Override
        public Object getCredentials() {
            return null;
        }
    }

    public static class CachedGoogleUser {
        private long creationTimeStamp;
        private GoogleUser googleUser;

        public CachedGoogleUser(GoogleUser googleUser) {
            this.googleUser = googleUser;
            creationTimeStamp = new Date().getTime();
        }

        boolean isNotTimedOut() {
            return (new Date().getTime() - creationTimeStamp) < 1800000; // 30 min
        }

        public GoogleUser getGoogleUser() {
            return googleUser;
        }
    }
}
