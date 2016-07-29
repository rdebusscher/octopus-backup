package be.c4j.ee.security.credentials.authentication.oauth2.fake;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;

/**
 *
 */
public interface FakeUserInfo {

    OAuth2User getUser(String token);
}
