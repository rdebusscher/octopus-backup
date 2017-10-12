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
package be.c4j.ee.security.twostep.otp;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.twostep.otp.config.OTPConfig;
import be.c4j.ee.security.twostep.otp.provider.DOTPProvider;
import be.c4j.ee.security.twostep.otp.provider.HOTPProvider;
import be.c4j.ee.security.twostep.otp.provider.TOTPProvider;
import be.c4j.ee.security.util.StringUtil;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 *
 */
@ApplicationScoped
public class OTPProviderFactory {

    @Inject
    private OTPConfig otpConfig;

    @Inject
    private StringUtil stringUtil;

    private OTPProvider otpProvider;

    public OTPProvider retrieveOTPProvider() {
        if (otpProvider == null) {
            otpProvider = createOTPProvider();
            Properties config = defineConfig();
            otpProvider.setProperties(otpConfig.getOTPLength(), config);
        }
        return otpProvider;
    }

    private Properties defineConfig() {
        Properties result = null;
        InputStream inputStream;
        String otpConfigFile = otpConfig.getOTPConfigFile();
        if (stringUtil.isEmpty(otpConfigFile)) {
            OctopusOTPAlgorithm algorithm = getOctopusOTPAlgorithm();
            if (algorithm != null) {
                switch (algorithm) {

                    case HOTP:
                        otpConfigFile = "/HOTPProvider.properties";
                        break;
                    case TOTP:
                        otpConfigFile = "/TOTPProvider.properties";
                        break;
                    case DOTP:
                        otpConfigFile = "/DOTPProvider.properties";
                        break;
                    case SOTP:
                        otpConfigFile = "/SOTPProvider.properties";
                        break;
                    default:
                        throw new IllegalArgumentException("Value supported " + algorithm);

                }
            }
            inputStream = OTPProviderFactory.class.getClassLoader().getResourceAsStream(otpConfigFile);
            try {
                if (inputStream == null) {
                    inputStream = new FileInputStream(otpConfigFile);
                }
            } catch (FileNotFoundException e) {
                throw new OctopusConfigurationException(e.getMessage());
            }

            result = new Properties();
            try {
                result.load(inputStream);
                inputStream.close();
            } catch (IOException e) {
                ;
                // Should not occur, TODO check this!!
            }
        }
        return result;
    }

    private OctopusOTPAlgorithm getOctopusOTPAlgorithm() {
        OctopusOTPAlgorithm algorithm = null;
        try {
            algorithm = OctopusOTPAlgorithm.valueOf(otpConfig.getOTPProvider());
        } catch (IllegalArgumentException e) {
            ;
            // We can't map it to an enum, so it should be the FQN of an OTPProvider
        }
        return algorithm;
    }

    private OTPProvider createOTPProvider() {
        OTPProvider result = null;

        OctopusOTPAlgorithm algorithm = getOctopusOTPAlgorithm();
        if (algorithm != null) {
            switch (algorithm) {

                case HOTP:
                    result = new HOTPProvider();
                    break;
                case TOTP:
                    result = new TOTPProvider();
                    break;
                case DOTP:
                    result = new DOTPProvider();
                    break;
                case SOTP:
                    break;
                default:
                    throw new IllegalArgumentException("Value supported " + algorithm);
            }
        } else {
            try {
                Class<?> aClass = Class.forName(otpConfig.getOTPProvider());
                result = (OTPProvider) aClass.newInstance();
            } catch (ClassNotFoundException e1) {
                throw new OctopusConfigurationException("Class not found :" + otpConfig.getOTPProvider());
            } catch (InstantiationException e1) {
                throw new OctopusConfigurationException("Instantiation Exception for " + otpConfig.getOTPProvider());
            } catch (IllegalAccessException e1) {
                throw new OctopusConfigurationException("Illegal access Exception during instantiation of " + otpConfig.getOTPProvider());
            }
        }
        return result;
    }
}
