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
package be.c4j.ee.security.twostep;

import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.realm.OctopusDefinedAuthenticationInfo;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
public class AuthenticationInfoForTwoStep implements OctopusDefinedAuthenticationInfo {

    @Inject
    private TwoStepConfig twoStepConfig;

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
        AuthenticationInfo authenticationInfo = null;
        if (twoStepConfig.getTwoStepAuthenticationActive()) {
            UserPrincipal userPrincipal = (UserPrincipal) SecurityUtils.getSubject().getPrincipal();
            if (userPrincipal != null && userPrincipal.needsTwoStepAuthentication()) {
                // When we are performing validation of the second step, we have already a Principal (unauthenticated)
                // TODO As long as we can't separate twoStep code to a module, TwoStepProvider is optional in a general case.
                TwoStepProvider twoStepProvider = BeanProvider.getContextualReference(TwoStepProvider.class);
                authenticationInfo = twoStepProvider.defineAuthenticationInfo(token, userPrincipal);
            }
        }
        return authenticationInfo;
    }
}
