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

import be.c4j.ee.security.credentials.authentication.jwt.config.JWTConfig;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.Scanner;

/**
 *
 */
@ApplicationScoped
public class JWKManager {

    @Inject
    private JWTConfig jwtConfig;

    private JWKSet jwkSet;

    @PostConstruct
    public void init() {
        jwkSet = readJWKSet();
    }

    private JWKSet readJWKSet() {
        JWKSet result;
        String jwkFile = jwtConfig.getLocationJWKFile();
        InputStream inputStream = JWKManager.class.getClassLoader().getResourceAsStream(jwkFile);
        try {
            if (inputStream == null) {
                inputStream = new FileInputStream(jwkFile);
            }
            String content = new Scanner(inputStream).useDelimiter("\\Z").next();
            result = JWKSet.parse(content);
        } catch (FileNotFoundException e) {
            throw new OctopusConfigurationException("JWK File not found at " + jwkFile);
        } catch (ParseException e) {
            throw new OctopusConfigurationException("Parsing the JWK file failed with " + e.getMessage());
        }
        return result;
    }

    public boolean existsApiKey(String apiKey) {
        return jwkSet.getKeyByKeyId(apiKey) != null;
    }

    public JWK getJWKForApiKey(String apiKey) {
        return jwkSet.getKeyByKeyId(apiKey);
    }

}
