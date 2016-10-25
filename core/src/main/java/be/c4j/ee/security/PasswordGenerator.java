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
package be.c4j.ee.security;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 *
 */
@ApplicationScoped
public class PasswordGenerator {

    private SecureRandom secureRandom;

    @PostConstruct
    public void init() {
        secureRandom = new SecureRandom();
    }

    public String generate(int size) {
        if (size < 1) {
            throw new IllegalArgumentException("password length should be at least 1. Mostly 8 is considered a good length");
        }

        StringBuilder password = new StringBuilder();
        while (password.length() <= size) {
            password.append(new BigInteger(130, secureRandom).toString(32));
        }
        return password.toString().substring(0, size);
    }
}
