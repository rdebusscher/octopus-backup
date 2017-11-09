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

import be.c4j.ee.security.exception.OctopusUnexpectedException;
import org.apache.shiro.crypto.UnknownAlgorithmException;
import org.apache.shiro.crypto.hash.SimpleHash;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 *
 */

public class SecretKeyHash extends SimpleHash {

    public SecretKeyHash(String keyFactoryName, Object credentials, Object salt, int hashIterations) {
        super(keyFactoryName, credentials, salt, hashIterations);
    }

    @Override
    protected byte[] hash(byte[] bytes, byte[] salt, int hashIterations) throws UnknownAlgorithmException {

        String keySecretName = SimpleHashFactory.getInstance().defineRealHashAlgorithmName(getAlgorithmName());
        SecretKeyFactory keyFactory = null;
        try {
            keyFactory = SecretKeyFactory.getInstance(keySecretName);
        } catch (NoSuchAlgorithmException e) {
            throw new OctopusUnexpectedException(e);
        }

        int keySizeBytes = 32; // TODO Config or calculated (should be related to the SHA version in use.)

        String text = new String(bytes, Charset.forName("UTF-8"));
        char[] chars = text.toCharArray();

        byte[] encoded = null;
        try {
            encoded = keyFactory.generateSecret(
                    new PBEKeySpec(chars, salt, hashIterations, keySizeBytes * 8)).getEncoded();
        } catch (InvalidKeySpecException e) {
            throw new OctopusUnexpectedException(e);
        }
        return encoded;
    }

    @Override
    protected MessageDigest getDigest(String algorithmName) throws UnknownAlgorithmException {
        throw new UnsupportedOperationException();
    }
}
