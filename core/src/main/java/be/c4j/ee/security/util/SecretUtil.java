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
package be.c4j.ee.security.util;

import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.codec.Base64;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.security.SecureRandom;

/**
 *
 */
@ApplicationScoped
public class SecretUtil {

    private SecureRandom secureRandom;

    @PostConstruct
    public void init() {
        secureRandom = new SecureRandom();
    }

    public String generateSecretBase64(int byteLength) {
        byte[] secret = new byte[byteLength];

        secureRandom.nextBytes(secret);
        return Base64.encodeToString(secret);
    }


    public static SecretUtil getInstance() {
        return BeanProvider.getContextualReference(SecretUtil.class);
    }

}
