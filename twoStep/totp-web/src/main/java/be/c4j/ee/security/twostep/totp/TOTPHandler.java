/*
 * Copyright 2014-2016 Rudy De Busscher (www.c4j.be)
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

import be.c4j.ee.security.twostep.otp.Base32;
import be.c4j.ee.security.twostep.otp.OTPProvider;
import be.c4j.ee.security.twostep.otp.OTPProviderFactory;
import be.c4j.ee.security.twostep.otp.OTPUserData;
import be.c4j.ee.security.twostep.totp.config.TOTPConfig;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.security.SecureRandom;

/**
 *
 */
@ApplicationScoped
public class TOTPHandler {

    @Inject
    private OTPProviderFactory otpProviderFactory;

    @Inject
    private TOTPConfig totpConfig;

    private SecureRandom secureRandom;
    private OTPProvider otpProvider;

    @PostConstruct
    public void init() {
        secureRandom = new SecureRandom();
        otpProvider = otpProviderFactory.retrieveOTPProvider();
    }

    public String generateSecret() {
        byte[] secret = new byte[totpConfig.getSecretLength()];
        secureRandom.nextBytes(secret);
        return Base32.encode(secret);
    }

    public boolean validateTOTPValue(OTPUserData otpUserData, String totpValue) {
        return otpProvider.valid(otpUserData, totpConfig.getWindow(), totpValue);
    }

}
