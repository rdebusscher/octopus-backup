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
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * http://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters/6481658#6481658
 */

public class AESTesting {

    private static final String SUBJECT = "JUnit AES Testing";
    private String aesSecret;

    private JWSSigner signer;
    private JWSVerifier verifier;

    @Before
    public void setup() throws NoSuchAlgorithmException, JOSEException {
        // HMAC
        SecureRandom random = new SecureRandom();
        byte[] sharedSecret = new byte[32];
        random.nextBytes(sharedSecret);

        String secretString = Base64.encode(sharedSecret).toString();
        signer = new MACSigner(secretString);

        verifier = new MACVerifier(secretString);

        // AES
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();

        aesSecret = Base64.encode(secretKey.getEncoded()).toString();

    }

    @Test
    public void testAES() throws JOSEException, ParseException {
        String token = createToken();
        System.out.println(token);

        assertThat(readToken(token)).isEqualTo(SUBJECT);

    }

    private String readToken(String token) throws ParseException, JOSEException {
        JWEObject jweObject = JWEObject.parse(token);

        // Decrypt with shared key
        Base64 aesSecret64 = new Base64(aesSecret);

        jweObject.decrypt(new AESDecrypter(aesSecret64.decode()));

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
                new JWEHeader.Builder(JWEAlgorithm.A256KW, EncryptionMethod.A128CBC_HS256)
                        .contentType("JWT") // required to signal nested JWT
                        .build(),
                new Payload(signedJWT));

        // Perform encryption
        Base64 aesSecret64 = new Base64(aesSecret);
        jweObject.encrypt(new AESEncrypter(aesSecret64.decode()));

        // Serialise to JWE compact form
        return jweObject.serialize();
    }

    private Date addSecondsToDate(int seconds, Date beforeTime) {

        long curTimeInMs = beforeTime.getTime();
        return new Date(curTimeInMs + (seconds * 1000));
    }


}
