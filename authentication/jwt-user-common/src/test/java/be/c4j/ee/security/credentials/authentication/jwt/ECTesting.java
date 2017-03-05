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
package be.c4j.ee.security.credentials.authentication.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.Before;
import org.junit.Test;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class ECTesting {

    private static final String SUBJECT = "JUnit AES Testing";


    private JWSSigner signer;
    private JWSVerifier verifier;

    private ECKey privateECKey;
    private ECPublicKey publicECKey;

    @Before
    public void setup() throws NoSuchAlgorithmException, JOSEException {
        // HMAC
        SecureRandom random = new SecureRandom();
        byte[] sharedSecret = new byte[32];
        random.nextBytes(sharedSecret);

        String secretString = Base64.encode(sharedSecret).toString();
        signer = new MACSigner(secretString);

        verifier = new MACVerifier(secretString);

        // EC
        privateECKey = make(new Algorithm("ES512"), ECKey.Curve.P_521, "JUnitTest");

        publicECKey = privateECKey.toECPublicKey();

    }

    @Test
    public void testAES() throws JOSEException, ParseException {
        String token = createToken();
        System.out.println(token);

        assertThat(readToken(token)).isEqualTo(SUBJECT);

    }

    private String readToken(String token) throws ParseException, JOSEException {
        JWEObject jweObject = JWEObject.parse(token);

        // Decrypt private key

        jweObject.decrypt(new ECDHDecrypter(privateECKey));

        // Extract payload
        SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();

        String result = null;
        if (signedJWT.verify(verifier)) {

            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            result = claimsSet.getSubject();

        }
        return result;
    }

    private String createToken() throws JOSEException {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);

        JWTClaimsSet.Builder claimSetBuilder = new JWTClaimsSet.Builder();
        claimSetBuilder.subject(SUBJECT);

        Date issueTime = new Date();
        claimSetBuilder.issueTime(issueTime);

        claimSetBuilder.expirationTime(addSecondsToDate(2, issueTime));


        SignedJWT signedJWT = new SignedJWT(header, claimSetBuilder.build());

        // Apply the HMAC

        signedJWT.sign(signer);

        // Create JWE object with signed JWT as payload
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A128CBC_HS256)
                        .contentType("JWT") // required to signal nested JWT
                        .build(),
                new Payload(signedJWT));

        // Perform encryption

        jweObject.encrypt(new ECDHEncrypter(publicECKey));

        // Serialise to JWE compact form
        return jweObject.serialize();
    }

    private Date addSecondsToDate(int seconds, Date beforeTime) {

        long curTimeInMs = beforeTime.getTime();
        return new Date(curTimeInMs + (seconds * 1000));
    }

    private static ECKey make(Algorithm keyAlg, ECKey.Curve curve, String kid) {

        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");

            generator.initialize(curve.toECParameterSpec());
            KeyPair keyPair = generator.generateKeyPair();

            ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
            ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

            return new ECKey.Builder(curve, pub)
                    .privateKey(priv)
                    .keyUse(KeyUse.ENCRYPTION)
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
