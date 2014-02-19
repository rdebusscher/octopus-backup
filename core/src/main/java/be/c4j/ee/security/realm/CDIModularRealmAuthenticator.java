package be.c4j.ee.security.realm;

import be.c4j.ee.security.event.CDIAuthenticationListener;
import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationListener;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;

public class CDIModularRealmAuthenticator extends ModularRealmAuthenticator {

    private boolean listenerConfigured = false;

    @Override
    protected AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {
        if (!listenerConfigured) {
            configureListener();
        }
        return super.doAuthenticate(authenticationToken);
    }

    private void configureListener() {
        AuthenticationListener listener = CodiUtils.getContextualReferenceByClass(CDIAuthenticationListener.class);
        getAuthenticationListeners().add(listener);
        listenerConfigured = true;
    }
}
