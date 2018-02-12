/*
 * Copyright 2014-2018 Rudy De Busscher
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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 *
 */
public class JWKManagerRSA {

    private JWKManagerRSA() {
    }

    public static void main(String[] args) {
        String keyId = UUID.randomUUID().toString();
        //JWK jwk = make(2048, KeyUse.SIGNATURE, new Algorithm("PS512"), keyId);
        JWK jwk = make(2048, KeyUse.ENCRYPTION, new Algorithm("PS512"), keyId);

        System.out.println("keyId");
        System.out.println(keyId);

        System.out.println("Private JWK");
        System.out.println(jwk.toJSONString());

        RSAKey rsaKey = (RSAKey) jwk;
        System.out.println("Private pkss#8 PEM");
        outputPrivatePEM(rsaKey);

        System.out.println("Public JWK");
        System.out.println(jwk.toPublicJWK().toJSONString());

        System.out.println("Public X509 PEM");
        outputPublicPEM(rsaKey);

    }

    private static void outputPublicPEM(RSAKey rsaKey) {
        try {
            System.out.println("-----BEGIN RSA PUBLIC KEY-----");
            byte[] encoded = Base64.encodeChunked(rsaKey.toRSAPublicKey().getEncoded());
            System.out.print(CodecSupport.toString(encoded));
            System.out.println("-----END RSA PUBLIC KEY-----");
        } catch (JOSEException e) {
            e.printStackTrace();
        }
    }

    private static void outputPrivatePEM(RSAKey rsaKey) {
        try {
            System.out.println("-----BEGIN RSA PRIVATE KEY-----");
            byte[] encoded = Base64.encodeChunked(rsaKey.toRSAPrivateKey().getEncoded());
            System.out.print(CodecSupport.toString(encoded));
            System.out.println("-----END RSA PRIVATE KEY-----");
        } catch (JOSEException e) {
            e.printStackTrace();
        }
    }

    private static RSAKey make(Integer keySize, KeyUse keyUse, Algorithm keyAlg, String kid) {

        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(keySize);
            KeyPair kp = generator.generateKeyPair();

            RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
            RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();

            return new RSAKey.Builder(pub)
                    .privateKey(priv)
                    .keyUse(keyUse)
                    .algorithm(keyAlg)
                    .keyID(kid)
                    .build();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }
}
