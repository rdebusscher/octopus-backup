/*
 * Copyright 2014-2017 Rudy De Busscher (www.c4j.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.c4j.ee.security.realm;

import be.c4j.ee.security.event.OctopusAuthenticationListener;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.token.PrincipalAuthorizationInfoAvailibility;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationListener;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.util.ThreadContext;

import static be.c4j.ee.security.OctopusConstants.AUTHORIZATION_INFO;
import static be.c4j.ee.security.realm.OctopusRealm.IN_AUTHORIZATION_FLAG;

public class OctopusRealmAuthenticator extends ModularRealmAuthenticator {

    private boolean listenerConfigured = false;

    private boolean authorizationInfoRequired = false;

    @Override
    protected AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {
        if (!listenerConfigured) {
            configureListeners();
            checkAuthorizationInfoMarkers();
        }
        return super.doAuthenticate(authenticationToken);
    }

    private void checkAuthorizationInfoMarkers() {
        authorizationInfoRequired = !BeanProvider.getContextualReferences(PrincipalAuthorizationInfoAvailibility.class, true).isEmpty();
    }

    private void configureListeners() {
        AuthenticationListener listener = BeanProvider.getContextualReference(OctopusAuthenticationListener.class);
        getAuthenticationListeners().add(listener);

        listenerConfigured = true;
    }

    @Override
    protected AuthenticationInfo doSingleRealmAuthentication(Realm realm, AuthenticationToken token) {
        AuthenticationInfo authenticationInfo = super.doSingleRealmAuthentication(realm, token);
        // At this point the user is authenticated, otherwise there was already an exception thrown.

        if (authorizationInfoRequired && realm instanceof OctopusRealm) {

            ThreadContext.put(IN_AUTHORIZATION_FLAG, new InAuthorization());
            try {
                OctopusRealm octopusRealm = (OctopusRealm) realm;
                AuthorizationInfo authorizationInfo = octopusRealm.doGetAuthorizationInfo(authenticationInfo.getPrincipals());

                UserPrincipal userPrincipal = (UserPrincipal) authenticationInfo.getPrincipals().getPrimaryPrincipal();
                userPrincipal.addUserInfo(AUTHORIZATION_INFO, authorizationInfo);

            } finally {

                ThreadContext.remove(IN_AUTHORIZATION_FLAG);
            }
        }

        return authenticationInfo;
    }

    public static class InAuthorization {

        private InAuthorization() {
        }
    }
}
