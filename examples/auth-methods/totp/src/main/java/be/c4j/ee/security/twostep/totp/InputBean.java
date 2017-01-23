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

import be.c4j.ee.security.messages.FacesMessages;
import be.c4j.ee.security.twostep.otp.Base32;
import be.c4j.ee.security.twostep.otp.OTPUserData;
import org.apache.deltaspike.core.api.scope.ViewAccessScoped;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Named;
import java.io.Serializable;

/**
 *
 */
@ViewAccessScoped
@Named
public class InputBean implements Serializable {

    @Inject
    private TOTPHandler totpHandler;

    @Inject
    private FacesMessages facesMessages;

    private String secret;
    private String totpValue;

    @PostConstruct
    public void init() {

        secret = totpHandler.generateSecret();
    }

    public String getTotpValue() {
        return totpValue;
    }

    public void setTotpValue(String totpValue) {
        this.totpValue = totpValue;
    }

    public String getSecret() {
        return secret;
    }

    public void check() {
        try {
            OTPUserData userData = new OTPUserData(Base32.decode(secret), null);

            boolean valid = totpHandler.validateTOTPValue(userData, totpValue);
            if (valid) {
                facesMessages.text("TOTP is valid").asInfo().show();
            } else {
                facesMessages.text("TOTP is NOT valid").asError().show();
            }
        } catch (Base32.DecodingException e) {
            e.printStackTrace();
        }
    }
}
