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

import be.c4j.ee.security.exception.OctopusConfigurationException;
import org.apache.shiro.crypto.hash.SimpleHash;

import javax.crypto.SecretKeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public class SimpleHashFactory {

    private static SimpleHashFactory INSTANCE;

    private KeyFactoryNameFactory factory;
    private Map<String, String> realHashAlgorithmNames;
    private Map<String, HashType> algorithmNameHashTypes;

    private SimpleHashFactory() {
        factory = KeyFactoryNameFactory.getInstance();
        realHashAlgorithmNames = new HashMap<String, String>();
        algorithmNameHashTypes = new HashMap<String, HashType>();
    }

    public static SimpleHashFactory getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new SimpleHashFactory();
        }
        return INSTANCE;
    }

    /**
     * @param hashAlgorithmName
     * @return
     * @throws OctopusConfigurationException when hash algorithm name is not supported.
     */
    public String defineRealHashAlgorithmName(String hashAlgorithmName) {
        String result = realHashAlgorithmNames.get(hashAlgorithmName);
        if (result != null) {
            return result;
        }
        try {
            MessageDigest.getInstance(hashAlgorithmName);
            result = hashAlgorithmName;
            algorithmNameHashTypes.put(hashAlgorithmName, HashType.HASH);
        } catch (NoSuchAlgorithmException e) {
            String keyFactoryName = factory.getKeyFactoryName(hashAlgorithmName);

            try {
                SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(keyFactoryName);
                result = keyFactoryName;
                algorithmNameHashTypes.put(hashAlgorithmName, HashType.KEY_FACTORY);
            } catch (NoSuchAlgorithmException e1) {
                throw new OctopusConfigurationException(String.format("Hash algorithm name unknown : %s", hashAlgorithmName));
            }

        }

        realHashAlgorithmNames.put(hashAlgorithmName, result);
        return result;
    }

    public SimpleHash defineHash(String hashAlgorithmName, Object source, Object salt, int hashIterations) {
        SimpleHash result;

        switch (algorithmNameHashTypes.get(hashAlgorithmName)) {

            case HASH:
                result = new SimpleHash(hashAlgorithmName, source, salt, hashIterations);
                break;
            case KEY_FACTORY:
                result = new SecretKeyHash(hashAlgorithmName, source, salt, hashIterations);
                break;
            default:
                throw new IllegalArgumentException(String.format("Hash type %s not supported", algorithmNameHashTypes.get(hashAlgorithmName)));
        }
        return result;
    }

    public int getDefaultHashIterations(String hashAlgorithmName) {
        if (algorithmNameHashTypes.get(hashAlgorithmName) == null) {
            defineRealHashAlgorithmName(hashAlgorithmName);
        }
        return algorithmNameHashTypes.get(hashAlgorithmName).defaultHashIterations;
    }

    private static enum HashType {
        HASH(1), KEY_FACTORY(1024);

        private int defaultHashIterations;

        HashType(int defaultHashIterations) {
            this.defaultHashIterations = defaultHashIterations;
        }


    }
}
