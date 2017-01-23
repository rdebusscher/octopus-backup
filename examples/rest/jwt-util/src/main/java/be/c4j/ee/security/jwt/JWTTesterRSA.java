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
 *
 */
package be.c4j.ee.security.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.Date;
import java.util.Scanner;

/**
 *
 */
public class JWTTesterRSA {

    public static void main(String[] args) throws IOException, ParseException, JOSEException {

        String privateContent = readFile("private_RSA.jwk");
        JWK publicJWK = JWK.parse(privateContent);

        String apiKey = publicJWK.getKeyID();
        System.out.println("x-api-key = " + apiKey);

        String token = createToken((RSAKey) publicJWK, apiKey);

        String publicContent = readFile("public_RSA.jwk");

        JWKSet jwkSet = JWKSet.parse(publicContent);

        JWK jwkForApiKey = jwkSet.getKeyByKeyId(apiKey);
        showTokenContent(apiKey, token, (RSAKey) jwkForApiKey);

    }

    private static void showTokenContent(String apiKey, String token, RSAKey jwkForApiKey) throws ParseException, JOSEException {
        // Parse token
        SignedJWT signedJWT = SignedJWT.parse(token);

        // CRtea verifier using the RSA key
        JWSVerifier verifier = new RSASSAVerifier(jwkForApiKey);

        if (signedJWT.verify(verifier)) {
            // Ok, token is not tampered with.
            System.out.println("Signing verified");

            System.out.println("KeyId in Header OK " + (signedJWT.getHeader().getKeyID().equals(apiKey)));

            System.out.println("Subject = " + signedJWT.getJWTClaimsSet().getSubject());
            System.out.println("Audience = " + signedJWT.getJWTClaimsSet().getAudience());

            System.out.println("expiration = " + signedJWT.getJWTClaimsSet().getExpirationTime());
            System.out.println("clientAddress = " + signedJWT.getJWTClaimsSet().getClaim("clientAddress"));

        }
    }

    private static String createToken(RSAKey publicJWK, String apiKey) throws JOSEException {
        // Create  signer
        JWSSigner signer = new RSASSASigner(publicJWK);

        // Prepare JWT with claims set
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder();
        claimsSetBuilder.subject("xDataScience");
        claimsSetBuilder.audience("OctopusApp");

        claimsSetBuilder.issueTime(new Date());
        claimsSetBuilder.expirationTime(new Date(new Date().getTime() + 60 * 1000));
        claimsSetBuilder.claim("clientAddress", "127.0.0.1");

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS512).type(JOSEObjectType.JWT).keyID(apiKey).build();
        SignedJWT signedJWT = new SignedJWT(header, claimsSetBuilder.build());

        // Apply the Signing protection
        signedJWT.sign(signer);

        // Serialize to compact form, produces something like
        String s = signedJWT.serialize();

        System.out.println("Token : " + s);

        return s;

    }

    private static String readFile(String fileName) {
        InputStream privateKeys = JWTTesterRSA.class.getClassLoader().getResourceAsStream(fileName);
        return new Scanner(privateKeys).useDelimiter("\\Z").next();
    }
}
