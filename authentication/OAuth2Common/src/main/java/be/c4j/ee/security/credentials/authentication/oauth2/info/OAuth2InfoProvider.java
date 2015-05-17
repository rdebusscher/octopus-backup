package be.c4j.ee.security.credentials.authentication.oauth2.info;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import org.scribe.model.Token;

import javax.servlet.http.HttpServletRequest;

/**
 *
 */
public interface OAuth2InfoProvider {

    OAuth2User retrieveUserInfo(Token token, HttpServletRequest req);
}
