package be.c4j.ee.security.credentials.authentication.oauth2.google.filter;

import be.c4j.ee.security.credentials.authentication.oauth2.google.json.GoogleJSONProcessor;
import be.c4j.ee.security.credentials.authentication.oauth2.google.provider.GoogleOAuth2ServiceProducer;
import be.rubus.web.jerry.provider.BeanProvider;
import org.apache.shiro.authc.AuthenticationToken;
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
        OAuthService authService = googleOAuth2ServiceProducer.createOAuthService(WebUtils.toHttp(request));

        Token token = new Token(authTokens[1], "");

        OAuthRequest oReq = new OAuthRequest(Verb.GET,
                "https://www.googleapis.com/oauth2/v2/userinfo");

        authService.signRequest(token, oReq);
        Response oResp = oReq.send();
        return jsonProcessor.extractGoogleUser(oResp.getBody());
    }


}
