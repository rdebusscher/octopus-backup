package be.c4j.ee.security.shiro;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * This is a marker interface. When applied to the AuthenticationToken, no CredentialMatcher is required.
 * Token implementing this interface are always interpreted as valid because they are created following a valid
 * authentication like OAuth2, JWT, ...
 */
public interface ValidatedAuthenticationToken extends AuthenticationToken {
}
