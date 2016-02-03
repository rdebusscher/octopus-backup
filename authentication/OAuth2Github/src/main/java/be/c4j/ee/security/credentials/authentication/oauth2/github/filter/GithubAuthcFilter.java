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
package be.c4j.ee.security.credentials.authentication.oauth2.github.filter;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.credentials.authentication.oauth2.application.ApplicationInfo;
import be.c4j.ee.security.credentials.authentication.oauth2.github.GithubProviderLiteral;
import be.c4j.ee.security.credentials.authentication.oauth2.info.OAuth2InfoProvider;
import be.c4j.ee.security.fake.LoginAuthenticationTokenProvider;
import be.rubus.web.jerry.provider.BeanProvider;
import com.github.scribejava.core.model.Token;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.mgt.CachingSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;

/**
 * FIXME See how we can Generify this.
 */
public class GithubAuthcFilter extends BasicHttpAuthenticationFilter {

    private OAuth2InfoProvider infoProvider;

    private LoginAuthenticationTokenProvider loginAuthenticationTokenProvider;

    /**
     * This class's private logger.
     */
    private static final Logger log = LoggerFactory.getLogger(BasicHttpAuthenticationFilter.class);

    public GithubAuthcFilter() {
        setAuthcScheme("Github OAuth2");
        setAuthzScheme("Bearer");
        infoProvider = BeanProvider.getContextualReference(OAuth2InfoProvider.class, false, new GithubProviderLiteral());
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
        OAuth2User oAuth2User = getCachedUser(authToken);

        if (oAuth2User == null) {
            oAuth2User = useFakeLogin(request, authToken);
        }

        if (oAuth2User == null) {
            // We don't have a cached version which is still valid.
            oAuth2User = getOauth2User(request, authToken);

            if (oAuth2User != null) {
                oAuth2User.setToken(new Token(authToken, ""));
                setCachedUser(authToken, oAuth2User);
            }
        }

        if (oAuth2User == null) {
            ((HttpServletResponse) response).setStatus(401);
            return new DummyOAuth2AuthenticationToken();
        }

        setApplication(oAuth2User);
        return oAuth2User;
    }

    private void setApplication(OAuth2User oAuth2User) {
        ApplicationInfo applicationInfo = BeanProvider.getContextualReference(ApplicationInfo.class, true);
        if (applicationInfo != null) {
            oAuth2User.setApplicationName(applicationInfo.getName());
        }

    }

    private OAuth2User useFakeLogin(ServletRequest request, String authToken) {
        OAuth2User result = null;
        if ("localhost".equals(request.getServerName()) && loginAuthenticationTokenProvider != null) {
            result = (OAuth2User) loginAuthenticationTokenProvider.determineAuthenticationToken(authToken);
        }
        return result;
    }

    private void setCachedUser(String authToken, OAuth2User oAuth2User) {
        Cache<String, CachedOAuth2User> cache = getCache();

        if (cache != null) {
            cache.put(authToken, new CachedOAuth2User(oAuth2User));
        }
    }

    private OAuth2User getOauth2User(ServletRequest request, String authToken) {
        Token token = new Token(authToken, "");

        return infoProvider.retrieveUserInfo(token, WebUtils.toHttp(request));
    }

    private OAuth2User getCachedUser(String authToken) {
        OAuth2User result = null;
        Cache<String, CachedOAuth2User> cache = getCache();

        if (cache != null) {
            CachedOAuth2User cachedOAuth2User = cache.get(authToken);
            if (cachedOAuth2User != null && cachedOAuth2User.isNotTimedOut()) {
                result = cachedOAuth2User.getUser();
            }
        }
        return result;
    }

    private Cache<String, CachedOAuth2User> getCache() {
        Cache<String, CachedOAuth2User> cache = null;
        SecurityManager securityManager = SecurityUtils.getSecurityManager();
        if (securityManager instanceof CachingSecurityManager) {
            CachingSecurityManager cachingSecurityManager = (CachingSecurityManager) securityManager;
            cache = cachingSecurityManager.getCacheManager().getCache("AuthenticationToken");


        }
        return cache;
    }


    public static class DummyOAuth2AuthenticationToken implements AuthenticationToken {

        @Override
        public Object getPrincipal() {
            return null;
        }

        @Override
        public Object getCredentials() {
            return null;
        }
    }

    public static class CachedOAuth2User {
        private long creationTimeStamp;
        private OAuth2User oAuth2User;

        public CachedOAuth2User(OAuth2User oAuth2User) {
            this.oAuth2User = oAuth2User;
            creationTimeStamp = new Date().getTime();
        }

        boolean isNotTimedOut() {
            return (new Date().getTime() - creationTimeStamp) < 1800000; // 30 min
        }

        public OAuth2User getUser() {
            return oAuth2User;
        }
    }
}
