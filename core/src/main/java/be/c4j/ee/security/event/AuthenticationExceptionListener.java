package be.c4j.ee.security.event;

import be.c4j.ee.security.exception.FrameworkConfigurationException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationListener;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.PrincipalCollection;

import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;

/**
 *
 */
public class AuthenticationExceptionListener implements AuthenticationListener {
    @Override
    public void onSuccess(AuthenticationToken token, AuthenticationInfo info) {
        // Only interested in failures due to configuration problems
    }

    @Override
    public void onFailure(AuthenticationToken token, AuthenticationException ae) {
        if (ae instanceof FrameworkConfigurationException) {
            FacesMessage fatalMsg = new FacesMessage(FacesMessage.SEVERITY_FATAL, ae.getMessage(), ae.getMessage());
            FacesContext.getCurrentInstance().addMessage(null, fatalMsg);
        }
    }

    @Override
    public void onLogout(PrincipalCollection principals) {
        // Only interested in failures due to configuration problems
    }
}
