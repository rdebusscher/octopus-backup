package be.c4j.ee.security.service;

import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class AuthenticationService {

    public boolean reauthenticate(String password) {
        UserPrincipal principal = (UserPrincipal) SecurityUtils.getSubject().getPrincipal();
        AuthenticationToken token = new UsernamePasswordToken(principal.getUserName(), password);
        boolean result = true;
        try {
            SecurityUtils.getSecurityManager().authenticate(token);
        } catch (AuthenticationException e) {
            result = false;
        }
        return result;
    }
}
