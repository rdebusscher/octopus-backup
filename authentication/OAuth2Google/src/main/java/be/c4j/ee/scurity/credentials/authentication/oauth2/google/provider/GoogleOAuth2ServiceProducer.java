package be.c4j.ee.scurity.credentials.authentication.oauth2.google.provider;

import be.c4j.ee.scurity.credentials.authentication.oauth2.google.OAuth2GoogleConfiguration;
import be.c4j.ee.scurity.credentials.authentication.oauth2.google.scribe.Google2Api;
import org.scribe.builder.ServiceBuilder;
import org.scribe.oauth.OAuthService;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
@ApplicationScoped
public class GoogleOAuth2ServiceProducer {

    @Inject
    private OAuth2GoogleConfiguration configuration;

    public OAuthService createOAuthService(HttpServletRequest req) {
        //Configure
        ServiceBuilder builder = new ServiceBuilder();
        OAuthService service = builder.provider(Google2Api.class)
                .apiKey(configuration.getClientId())
                .apiSecret(configuration.getClientSecret())
                .callback(assembleCallbackUrl(req))
                .scope("openid profile email " +
                        "https://www.googleapis.com/auth/plus.login " +
                        "https://www.googleapis.com/auth/plus.me")
                .debug()
                .build(); //Now build the call

        return service;
    }

    private String assembleCallbackUrl(HttpServletRequest req) {
        StringBuilder result = new StringBuilder();
        result.append(req.getScheme()).append("://");
        result.append(req.getServerName()).append(':');
        result.append(req.getServerPort());
        result.append(req.getContextPath()).append("/oauth2callback");
        return result.toString();
    }
}
