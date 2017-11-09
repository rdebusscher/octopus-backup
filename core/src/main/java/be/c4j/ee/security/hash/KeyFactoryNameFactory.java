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
package be.c4j.ee.security.hash;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 *
 */
public class KeyFactoryNameFactory {

    private static String JAVA_VERSION = Runtime.class.getPackage().getSpecificationVersion();
    private static KeyFactoryNameFactory INSTANCE;

    private Map<String, Map<String, String>> defaultKeyFactoryNames;

    private KeyFactoryNameFactory() {
        defaultKeyFactoryNames = new HashMap<String, Map<String, String>>();
        definePBKDF2Names();
    }

    private void definePBKDF2Names() {
        Map<String, String> mapping = new HashMap<String, String>();

        mapping.put("1.7", "PBKDF2WithHmacSHA1");
        mapping.put("1.8", "PBKDF2WithHmacSHA256");

        defaultKeyFactoryNames.put("PBKDF2", mapping);
    }

    public String getKeyFactoryName(String name) {
        String nameUpperCase = name.toUpperCase(Locale.ENGLISH);
        String result;

        if (defaultKeyFactoryNames.containsKey(nameUpperCase)) {
            result = defaultKeyFactoryNames.get(nameUpperCase).get(JAVA_VERSION);
        } else {
            result = name;
        }
        return result;
    }

    public static KeyFactoryNameFactory getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new KeyFactoryNameFactory();
        }
        return INSTANCE;
    }
}
