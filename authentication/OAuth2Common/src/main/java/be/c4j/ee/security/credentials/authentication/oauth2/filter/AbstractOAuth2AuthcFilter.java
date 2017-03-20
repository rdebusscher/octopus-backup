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
package be.c4j.ee.security.credentials.authentication.oauth2.filter;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.credentials.authentication.oauth2.application.ApplicationInfo;
import be.c4j.ee.security.credentials.authentication.oauth2.info.OAuth2InfoProvider;
import be.c4j.ee.security.fake.LoginAuthenticationTokenProvider;
import be.c4j.ee.security.token.IncorrectDataToken;
import com.github.scribejava.core.model.OAuth2AccessToken;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.mgt.CachingSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;

/**
 * Contains the generic code for the Authc Filters using OAuth2 (Google, Github, LinkedIn).
 * TODO Verify if BasicHttpAuthenticationFilter is the correct class and AuthenticatingFilter is not the preferred one.
 */
public abstract class AbstractOAuth2AuthcFilter extends BasicHttpAuthenticationFilter implements Initializable {

    /**
     * This class's logger.
     */
    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    private LoginAuthenticationTokenProvider loginAuthenticationTokenProvider;

    public AbstractOAuth2AuthcFilter() {
        setAuthzScheme("Bearer");
        loginAuthenticationTokenProvider = BeanProvider.getContextualReference(LoginAuthenticationTokenProvider.class, true);
    }

    protected abstract OAuth2InfoProvider getInfoProvider();

    @Override
    public void init() throws ShiroException {
        // Register this filter with the OAuth2AuthcFilterManager so that the OAuth2AuthcFilter can forward to the correct filter.
        OAuth2AuthcFilterManager filterManager = BeanProvider.getContextualReference(OAuth2AuthcFilterManager.class);
        filterManager.registerFilter(this);
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
        String authorizationHeader = getAuthzHeader(request);
        if (authorizationHeader == null || authorizationHeader.length() == 0) {
            return new IncorrectDataToken("No Authorization header found on the request");
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Attempting to execute login with headers [" + authorizationHeader + "]");
        }

        String[] authTokens = authorizationHeader.split(" ");
        if (authTokens.length < 2) {
            return new IncorrectDataToken("Invalid structure of the Authorization header on the request");
        }

        String authToken = authTokens[1];
        OAuth2User oauth2User = getCachedOAuth2User(authToken);

        if (oauth2User == null) {
            oauth2User = useFakeLogin(request, authToken);
        }

        if (oauth2User == null) {
            // We don't have a cached version which is still valid.
            oauth2User = getOAuth2User(request, authToken);

            if (oauth2User != null) {
                oauth2User.setToken(new OAuth2AccessToken(authToken));
                setCachedOAuth2User(authToken, oauth2User);
            }
        }

        if (oauth2User == null) {
            // FIXME Check Iof this status setting is required.
            ((HttpServletResponse) response).setStatus(401);
            return new IncorrectDataToken("Unable to create the Authentication token based on the request info");
        }

        setApplication(oauth2User);
        return oauth2User;
    }

    private void setApplication(OAuth2User oAuth2User) {
        ApplicationInfo applicationInfo = BeanProvider.getContextualReference(ApplicationInfo.class, true);
        if (applicationInfo != null) {
            oAuth2User.setApplicationName(applicationInfo.getName());
        }
    }

    private void setCachedOAuth2User(String authToken, OAuth2User oauth2User) {
        Cache<String, CachedOAuth2User> cache = getCache();

        if (cache != null) {
            cache.put(authToken, new CachedOAuth2User(oauth2User));
        }
    }

    private OAuth2User getOAuth2User(ServletRequest request, String authToken) {
        OAuth2AccessToken token = new OAuth2AccessToken(authToken);

        return getInfoProvider().retrieveUserInfo(token, WebUtils.toHttp(request));
    }

    private OAuth2User useFakeLogin(ServletRequest request, String authToken) {
        OAuth2User result = null;
        if ("localhost".equals(request.getServerName()) && loginAuthenticationTokenProvider != null) {
            result = (OAuth2User) loginAuthenticationTokenProvider.determineAuthenticationToken(authToken);
        }
        return result;
    }

    private OAuth2User getCachedOAuth2User(String authToken) {
        OAuth2User result = null;
        Cache<String, CachedOAuth2User> cache = getCache();

        if (cache != null) {
            CachedOAuth2User cachedOAuth2User = cache.get(authToken);
            if (cachedOAuth2User != null && cachedOAuth2User.isNotTimedOut()) {
                result = cachedOAuth2User.getOAuth2User();
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

        public OAuth2User getOAuth2User() {
            return oAuth2User;
        }
    }

}
