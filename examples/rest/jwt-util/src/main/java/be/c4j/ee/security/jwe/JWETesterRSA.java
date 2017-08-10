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
package be.c4j.ee.security.jwe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;

/**
 *
 */

public class JWETesterRSA {


    public static void main(String[] args) throws JOSEException, ParseException {
        String apiKey = "apiKey";

        RSAKey rsaJWK = makeRSA(2018, KeyUse.SIGNATURE, new Algorithm("PS512"), apiKey);

        RSAKey rsaEncJWK = makeRSA(2018, KeyUse.ENCRYPTION, new Algorithm("PS512"), apiKey);

        SignedJWT signedJWT = createSignedJWT(apiKey, rsaJWK);

        String token = createEncryptedJWE(rsaEncJWK, signedJWT);

        System.out.println(token);

        EncryptedJWT encryptedJWT = EncryptedJWT.parse(token);

        // Create verifier using the RSA key
        JWEDecrypter decrypter = new RSADecrypter(rsaEncJWK.toRSAPrivateKey());
        encryptedJWT.decrypt(decrypter);

        // After decrypting, we can get the payload which is a SignedJWT.
        Payload payload = encryptedJWT.getPayload();
        SignedJWT jwt = payload.toSignedJWT();

        // Create verifier using the RSA key
        JWSVerifier verifier = new RSASSAVerifier(rsaJWK.toPublicJWK());

        if (jwt.verify(verifier)) {
            System.out.println("Signing verified");

            System.out.println("KeyId in Header OK " + (jwt.getHeader().getKeyID().equals(apiKey)));

            System.out.println("Subject = " + jwt.getJWTClaimsSet().getSubject());
            System.out.println("Audience = " + jwt.getJWTClaimsSet().getAudience());

            System.out.println("expiration = " + jwt.getJWTClaimsSet().getExpirationTime());
            System.out.println("custom = " + jwt.getJWTClaimsSet().getClaim("custom"));

        };

    }

    private static String createEncryptedJWE(RSAKey rsaEncJWK, SignedJWT signedJWT) throws JOSEException {
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256CBC_HS512)
                        .contentType("JWT") // required to signal nested JWT
                        .build(),
                new Payload(signedJWT));

        // Perform encryption
        jweObject.encrypt(new RSAEncrypter(rsaEncJWK));

        // Serialise to JWE compact form
        return jweObject.serialize();
    }

    private static SignedJWT createSignedJWT(String apiKey, RSAKey rsaJWK) throws JOSEException {
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder();
        claimsSetBuilder.subject("Subject");
        claimsSetBuilder.audience("Audience");

        Date issueTime = new Date();
        claimsSetBuilder.issueTime(issueTime);

        claimsSetBuilder.expirationTime(new Date(System.currentTimeMillis() + 1000));

        claimsSetBuilder.claim("custom", "CustomClaimValue");

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS512).type(JOSEObjectType.JWT).keyID(apiKey).build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSetBuilder.build());

        // Apply the Signing protection

        JWSSigner signer = new RSASSASigner(rsaJWK);

        signedJWT.sign(signer);
        return signedJWT;
    }

    private static RSAKey makeRSA(Integer keySize, KeyUse keyUse, Algorithm keyAlg, String kid) {

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
