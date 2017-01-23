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
package be.c4j.ee.security.salt;

import be.c4j.ee.security.config.OctopusConfig;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.security.SecureRandom;

@ApplicationScoped
public class SaltHashingUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(SaltHashingUtil.class);

    private int saltLength;

    @Inject
    private OctopusConfig config;

    private SecureRandom sr;

    @PostConstruct
    public void init() {
        try {
            saltLength = Integer.valueOf(config.getSaltLength());
        } catch (NumberFormatException e) {
            LOGGER.warn("Salt length config parameter can't be converted to integer (value = " + config.getSaltLength()
                    + ") 16 is taken as value");
        }
        sr = new SecureRandom();
    }

    public byte[] nextSalt() {
        byte[] salt = new byte[saltLength];
        sr.nextBytes(salt);
        return salt;
    }

    public String hash(String password, byte[] salt) {
        HashEncoding hashEncoding = config.getHashEncoding();

        String result;
        switch (hashEncoding) {

            case HEX:
                result = hashInHex(password, salt);
                break;
            case BASE64:
                result = hashInBase64(password, salt);
                break;
            default:
                throw new IllegalArgumentException("hashEncoding " + hashEncoding + " not supported");
        }
        return result;
    }

    public String hashInHex(String password, byte[] salt) {
        SimpleHash hash = new SimpleHash(config.getHashAlgorithmName(), password, salt);
        return hash.toHex();
    }

    public String hashInBase64(String password, byte[] salt) {
        SimpleHash hash = new SimpleHash(config.getHashAlgorithmName(), password, salt);
        return hash.toBase64();
    }

}
