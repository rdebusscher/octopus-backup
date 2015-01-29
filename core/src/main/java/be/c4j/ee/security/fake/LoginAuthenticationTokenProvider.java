package be.c4j.ee.security.fake;

import org.apache.shiro.authc.AuthenticationToken;

/**
 *
 */
public interface LoginAuthenticationTokenProvider {

    AuthenticationToken determineAuthenticationToken(String loginData);
}
