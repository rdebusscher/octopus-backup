package be.c4j.ee.security.credentials.authentication.fake;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.credentials.authentication.oauth2.fake.FakeUserInfo;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
public class OctopusFakeUserInfo implements FakeUserInfo {

    @Inject
    private OAuth2TokenStore tokenStore;

    @Override
    public OAuth2User getUser(String token) {
        return tokenStore.retrieveUser(token);
    }
}
