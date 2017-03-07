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
package be.c4j.ee.security.jwt;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.UUID;

/**
 *
 */
public class JWKManagerEC {

    public static void main(String[] args) {
        String xApiKey = UUID.randomUUID().toString();
        //JWK jwk = make(KeyUse.SIGNATURE, new Algorithm("ES512"), ECKey.Curve.P_521, xApiKey);
        JWK jwk = make(KeyUse.ENCRYPTION, new Algorithm("ES512"), ECKey.Curve.P_521, xApiKey);

        System.out.println("x-api-key");
        System.out.println(xApiKey);

        System.out.println("Private");
        System.out.println(jwk.toJSONString());

        System.out.println("Public");
        System.out.println(jwk.toPublicJWK().toJSONString());
    }

    private static ECKey make(KeyUse keyUse, Algorithm keyAlg, ECKey.Curve curve, String kid) {

        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");

            generator.initialize(curve.toECParameterSpec());
            KeyPair keyPair = generator.generateKeyPair();

            ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
            ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

            return new ECKey.Builder(curve, pub)
                    .privateKey(priv)
                    .keyUse(keyUse)
                    .algorithm(keyAlg)
                    .keyID(kid) // Give the key some ID (optional)
                    .build();
        } catch (InvalidAlgorithmParameterException e) {

            e.printStackTrace();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
