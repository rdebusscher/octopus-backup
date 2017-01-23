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
 *
 */
package be.c4j.ee.security.twostep.totp;

import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.twostep.TwoStepAuthenticationInfo;
import be.c4j.ee.security.twostep.TwoStepProvider;
import be.c4j.ee.security.twostep.otp.OTPUserData;
import be.c4j.ee.security.twostep.otp.persistence.OTPUserDataPersistence;
import be.c4j.ee.security.twostep.totp.matcher.TOTPCredentialsMatcher;
import org.apache.shiro.authc.AuthenticationToken;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
@ApplicationScoped
public class TOTPTwoStepProvider implements TwoStepProvider {

    @Inject
    private TOTPHandler handler;

    @Inject
    private OTPUserDataPersistence userDataPersistence;

    @Override
    public void startSecondStep(HttpServletRequest request, UserPrincipal userPrincipal) {
        // Nothing to do
    }

    @Override
    public TwoStepAuthenticationInfo defineAuthenticationInfo(AuthenticationToken token, UserPrincipal userPrincipal) {
        OTPUserData userData = userDataPersistence.retrieveData(userPrincipal);
        return new TwoStepAuthenticationInfo(new TOTPCredentialsMatcher(handler, userData));
    }
}
