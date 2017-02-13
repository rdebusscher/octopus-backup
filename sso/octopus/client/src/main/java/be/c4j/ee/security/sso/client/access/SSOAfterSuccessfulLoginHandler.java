package be.c4j.ee.security.sso.client.access;

import be.c4j.ee.security.access.AfterSuccessfulLoginHandler;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
public class SSOAfterSuccessfulLoginHandler implements AfterSuccessfulLoginHandler {

    @Inject
    private OctopusSSOClientConfiguration ssoClientConfiguration;

    @Override
    public void onSuccessfulLogin(AuthenticationToken token, AuthenticationInfo info, Subject subject) {
        String accessPermission = ssoClientConfiguration.getAccessPermission();
        if (accessPermission != null && !accessPermission.isEmpty()) {
            subject.checkPermission(accessPermission);
        }
    }
}
