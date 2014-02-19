package be.c4j.ee.security.event;

import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationListener;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.PrincipalCollection;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Event;
import javax.inject.Inject;

@ApplicationScoped

public class CDIAuthenticationListener implements AuthenticationListener {

    @Inject
    private Event<LogonEvent> logonEvent;

    @Inject
    private Event<LogonFailureEvent> logonFailureEvent;

    @Inject
    private Event<LogoutEvent> logoutEvent;

    @Override
    public void onSuccess(AuthenticationToken token, AuthenticationInfo info) {
        LogonEvent event = new LogonEvent(token, info);
        logonEvent.fire(event);
    }

    @Override
    public void onFailure(AuthenticationToken token, AuthenticationException ae) {
        LogonFailureEvent event = new LogonFailureEvent(token, ae);
        logonFailureEvent.fire(event);
    }

    @Override
    public void onLogout(PrincipalCollection principals) {
        LogoutEvent event = new LogoutEvent((UserPrincipal) principals.getPrimaryPrincipal());
        logoutEvent.fire(event);
    }
}
