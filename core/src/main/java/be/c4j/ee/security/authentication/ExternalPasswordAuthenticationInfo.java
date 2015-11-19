package be.c4j.ee.security.authentication;

import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;

/**
 *
 */
public class ExternalPasswordAuthenticationInfo extends SimpleAuthenticationInfo {

    private static Logger LOGGER = LoggerFactory.getLogger(ExternalPasswordAuthenticationInfo.class);

    public ExternalPasswordAuthenticationInfo(Object principal, String realmName) {
        this.principals = new SimplePrincipalCollection(principal, realmName);
    }

    public void addUserInfo(Serializable key, Serializable value) {
        Object primaryPrincipal = getPrincipals().getPrimaryPrincipal();
        if (primaryPrincipal instanceof UserPrincipal) {
            ((UserPrincipal) primaryPrincipal).addUserInfo(key, value);
        } else {
            LOGGER.info("Adding user info is only possible on an Octopus Principal. Type of principal is " + primaryPrincipal.getClass().getName());
        }
    }

    public void setName(String name) {
        Object primaryPrincipal = getPrincipals().getPrimaryPrincipal();
        if (primaryPrincipal instanceof UserPrincipal) {
            ((UserPrincipal) primaryPrincipal).setName(name);
        } else {
            LOGGER.info("Set name is only possible on an Octopus Principal. Type of principal is " + primaryPrincipal.getClass().getName());

        }
    }
}
