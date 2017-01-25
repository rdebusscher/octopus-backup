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
package be.c4j.ee.security.twostep.otp.provider;

import be.c4j.ee.security.twostep.otp.Base32;
import be.c4j.ee.security.twostep.otp.OTPProvider;
import be.c4j.ee.security.twostep.otp.OTPUserData;

import java.security.SecureRandom;
import java.util.Properties;

/**
 *
 */
public class SOTPProvider implements OTPProvider {

    private SecureRandom secureRandom = new SecureRandom();

    private int digits;

    @Override
    public String generate(OTPUserData data) {
        long byteLength = Math.round(digits * 5.0 / 8.0);
        byte[] buffer = new byte[(int) byteLength];
        secureRandom.nextBytes(buffer);

        return Base32.encode(buffer).substring(0, digits);
    }

    @Override
    public void setProperties(int digits, Properties properties) {

        this.digits = digits;
    }

    @Override
    public boolean supportValidate() {
        return false;
    }

    @Override
    public boolean valid(OTPUserData data, int window, String userOTP) {
        return false;
    }
}
