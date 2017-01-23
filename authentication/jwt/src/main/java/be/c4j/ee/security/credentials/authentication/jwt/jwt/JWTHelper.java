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
package be.c4j.ee.security.credentials.authentication.jwt.jwt;

import be.c4j.ee.security.credentials.authentication.jwt.CheckJWTClaims;
import be.c4j.ee.security.credentials.authentication.jwt.JWTUser;
import be.c4j.ee.security.credentials.authentication.jwt.config.JWTConfig;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.systemaccount.SystemAccountAuthenticationToken;
import be.c4j.ee.security.systemaccount.SystemAccountPrincipal;
import be.c4j.ee.security.token.IncorrectDataToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.CredentialsException;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.*;

/**
 *
 */
@ApplicationScoped
public class JWTHelper {

    @Inject
    private JWKManager jwkManager;

    @Inject
    private JWTConfig jwtConfig;

    private CheckJWTClaims checkJWTClaims;

    private Map<String, List<String>> systemAccountsMapping;

    @PostConstruct
    public void init() {
        checkJWTClaims = BeanProvider.getContextualReference(CheckJWTClaims.class, true);

        systemAccountsMapping = new HashMap<String, List<String>>();

        String accountsMapFile = jwtConfig.getSystemAccountsMapFile();

        InputStream inputStream = JWKManager.class.getClassLoader().getResourceAsStream(accountsMapFile);
        try {
            if (inputStream == null) {
                inputStream = new FileInputStream(accountsMapFile);
            }

            Properties properties = new Properties();
            properties.load(inputStream);

            String systemAccounts;
            for (String key : properties.stringPropertyNames()) {
                systemAccounts = properties.getProperty(key);
                systemAccountsMapping.put(key, Arrays.asList(systemAccounts.split(",")));
            }
        } catch (IOException e) {
            throw new OctopusConfigurationException(e.getMessage());
        }

    }

    public AuthenticationToken createOctopusToken(HttpServletRequest request, String apiKey, String jwtToken) {
        AuthenticationToken result = null;
        JWK jwkForApiKey = jwkManager.getJWKForApiKey(apiKey);
        try {
            SignedJWT signedJWT = SignedJWT.parse(jwtToken);

            JWSVerifier verifier = new RSASSAVerifier((RSAKey) jwkForApiKey);
            if (signedJWT.verify(verifier) && signedJWT.getHeader().getKeyID().equals(apiKey)) {

                Map<String, Object> headerParams = signedJWT.getHeader().getCustomParams();

                Map<String, Object> claims = signedJWT.getJWTClaimsSet().getClaims();

                if (checkJWTClaims != null) {
                    checkJWTClaims.areClaimsValid(request, headerParams, claims);
                }

                String subject = signedJWT.getJWTClaimsSet().getSubject();

                if (systemAccountsMapping.containsKey(apiKey) && systemAccountsMapping.get(apiKey).contains(subject)) {
                    result = new SystemAccountAuthenticationToken(new SystemAccountPrincipal(subject));
                } else {
                    if (jwtConfig.isSystemAccountsOnly()) {
                        result = new IncorrectDataToken("Access denied for " + subject);
                    } else {
                        signedJWT.getHeader().getCriticalParams();
                        result = new JWTUser(subject);

                    }
                }

            }
        } catch (ParseException e) {
            throw new CredentialsException(e.getMessage());
        } catch (JOSEException e) {
            throw new CredentialsException(e.getMessage());
        }
        return result;
    }

}
