package be.c4j.ee.security.credentials.authentication.oauth2.google.filter;

import be.c4j.ee.security.credentials.authentication.oauth2.google.GoogleUser;
import be.c4j.ee.security.credentials.authentication.oauth2.google.json.GoogleJSONProcessor;
import be.c4j.ee.security.credentials.authentication.oauth2.google.provider.GoogleOAuth2ServiceProducer;
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

    /**
     * This class's private logger.
     */
    private static final Logger log = LoggerFactory.getLogger(BasicHttpAuthenticationFilter.class);

    public GoogleAuthcFilter() {
        setAuthcScheme("Google OAuth2");
        setAuthzScheme("Bearer");
        googleOAuth2ServiceProducer = BeanProvider.getContextualReference(GoogleOAuth2ServiceProducer.class, false);
        jsonProcessor = BeanProvider.getContextualReference(GoogleJSONProcessor.class, false);
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
            // We don't have a cached version which is still valid.
            googleUser = getGoogleUser(request, authToken);

            if (googleUser != null) {
                setCachedGoogleUser(authToken, googleUser);
            }
        }

        if (googleUser == null) {
            ((HttpServletResponse) response).setStatus(401);
            return new DummyGoogleAuthenticationToken();
        } else {

            return googleUser;
        }
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
