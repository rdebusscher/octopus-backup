package be.c4j.ee.security.access;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;

/**
 * Describe in this block the functionality of the class.
 * Created by rubus on 13/02/17.
 */

public interface AfterSuccessfulLoginHandler {

    void onSuccessfulLogin(AuthenticationToken token, AuthenticationInfo info, Subject subject);
}
