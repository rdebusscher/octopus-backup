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
package be.c4j.ee.security.sso.client;

import com.nimbusds.jose.util.Base64;

import java.security.SecureRandom;

/**
 *
 */

public class GenerateClientSecret {


    private static String generateSecret(int length) {
        byte[] secret = new byte[length];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(secret);
        return Base64.encode(secret).toString();

    }

    public static void main(String[] args) {

        System.out.println("HS256 : " + generateSecret(32));
        System.out.println("HS384 : " + generateSecret(48));
        System.out.println("HS512 : " + generateSecret(64));

    }

}
