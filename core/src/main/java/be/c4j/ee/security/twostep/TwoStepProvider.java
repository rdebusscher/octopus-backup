package be.c4j.ee.security.twostep;

import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.authc.AuthenticationToken;

import javax.servlet.http.HttpServletRequest;

/**
 *
 */
public interface TwoStepProvider {

    void startSecondStep(HttpServletRequest request, UserPrincipal userPrincipal);

    TwoStepAuthenticationInfo defineAuthenticationInfo(AuthenticationToken token, UserPrincipal userPrincipal);
}
