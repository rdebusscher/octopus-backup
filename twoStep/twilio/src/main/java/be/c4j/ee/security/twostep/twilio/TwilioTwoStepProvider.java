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
package be.c4j.ee.security.twostep.twilio;

import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.twostep.TwoStepAuthenticationInfo;
import be.c4j.ee.security.twostep.TwoStepProvider;
import be.c4j.ee.security.twostep.otp.OTPProvider;
import be.c4j.ee.security.twostep.otp.OTPProviderFactory;
import be.c4j.ee.security.twostep.otp.config.OTPConfig;
import be.c4j.ee.security.twostep.otp.persistence.OTPUserDataPersistence;
import be.c4j.ee.security.twostep.twilio.matcher.SimpleTwoStepMatcher;
import org.apache.shiro.authc.AuthenticationToken;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class TwilioTwoStepProvider implements TwoStepProvider {

    @Inject
    private OTPProviderFactory otpProviderFactory;

    @Inject
    private OTPUserDataPersistence otpUserDataPersistence;

    @Inject
    private SMSSender smsSender;

    @Inject
    private OTPConfig otpConfig;

    // TODO Do we need a separate store for this?
    private Map<Serializable, String> otpValues = new HashMap<Serializable, String>();

    @Override
    public void startSecondStep(HttpServletRequest request, UserPrincipal userPrincipal) {
        String mobileNumber = userPrincipal.getMobileNumber();
        if (mobileNumber == null || mobileNumber.isEmpty()) {
            // FIXME
        }
        OTPProvider provider = otpProviderFactory.retrieveOTPProvider();

        String otpValue = provider.generate(otpUserDataPersistence.retrieveData(userPrincipal));
        smsSender.sendSMS(userPrincipal, otpValue);
        otpValues.put(userPrincipal.getId(), otpValue);
    }

    @Override
    public TwoStepAuthenticationInfo defineAuthenticationInfo(AuthenticationToken token, UserPrincipal userPrincipal) {
        String value = otpValues.get(userPrincipal.getId());
        otpValues.remove(userPrincipal.getId()); // Make sure it can't be retrieved a second time!!
        return new TwoStepAuthenticationInfo(new SimpleTwoStepMatcher(value));
    }

}
