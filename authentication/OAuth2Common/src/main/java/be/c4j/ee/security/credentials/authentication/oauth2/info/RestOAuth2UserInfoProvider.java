package be.c4j.ee.security.credentials.authentication.oauth2.info;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;

import java.util.Map;

/**
 *
 */
public interface RestOAuth2UserInfoProvider {

    Map<String, String> defineInfo(OAuth2User user);
}
