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
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationListener;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;

public class OctopusRealmAuthenticator extends ModularRealmAuthenticator {

    private boolean listenerConfigured = false;

    @Override
    protected AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {
        if (!listenerConfigured) {
            configureListeners();
        }
        return super.doAuthenticate(authenticationToken);
    }

    private void configureListeners() {
        AuthenticationListener listener = BeanProvider.getContextualReference(OctopusAuthenticationListener.class);
        getAuthenticationListeners().add(listener);

        listenerConfigured = true;
    }
}
