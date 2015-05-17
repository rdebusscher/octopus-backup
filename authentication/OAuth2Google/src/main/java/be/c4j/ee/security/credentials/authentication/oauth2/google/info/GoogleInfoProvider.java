package be.c4j.ee.security.credentials.authentication.oauth2.google.info;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.credentials.authentication.oauth2.google.GoogleProvider;
import be.c4j.ee.security.credentials.authentication.oauth2.google.json.GoogleJSONProcessor;
import be.c4j.ee.security.credentials.authentication.oauth2.google.provider.GoogleOAuth2ServiceProducer;
import be.c4j.ee.security.credentials.authentication.oauth2.info.OAuth2InfoProvider;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.oauth.OAuthService;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
@ApplicationScoped
@GoogleProvider
public class GoogleInfoProvider implements OAuth2InfoProvider {

    @Inject
    private GoogleOAuth2ServiceProducer googleOAuth2ServiceProducer;

    @Inject
    private GoogleJSONProcessor jsonProcessor;


    @Override
    public OAuth2User retrieveUserInfo(Token token, HttpServletRequest req) {

        OAuthRequest oReq = new OAuthRequest(Verb.GET, "https://www.googleapis.com/oauth2/v2/userinfo");

        OAuthService authService = googleOAuth2ServiceProducer.createOAuthService(req);
        authService.signRequest(token, oReq);
        Response oResp = oReq.send();
        OAuth2User googleUser = jsonProcessor.extractGoogleUser(oResp.getBody());
        if (googleUser != null) {
            googleUser.setToken(token);
        }
        return googleUser;
    }
}
