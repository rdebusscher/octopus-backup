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

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.jwt.config.JWTConfig;
import be.c4j.ee.security.util.StringUtil;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
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

    @Inject
    private StringUtil stringUtil;

    private JWKSet jwkSet;

    @PostConstruct
    public void init() {
        jwkSet = readJWKSet();
    }

    private JWKSet readJWKSet() {
        JWKSet result;
        String jwkFile = jwtConfig.getLocationJWKFile();
        if (stringUtil.isEmpty(jwkFile)) {
            throw new OctopusConfigurationException("A value for the parameter jwk.file is required");
        }

        InputStream inputStream = JWKManager.class.getClassLoader().getResourceAsStream(jwkFile);
        try {
            if (inputStream == null) {
                inputStream = new FileInputStream(jwkFile);
            }
            String content = new Scanner(inputStream).useDelimiter("\\Z").next();
            result = JWKSet.parse(content);
        } catch (FileNotFoundException e) {
            throw new OctopusConfigurationException(String.format("JWK File not found at %s", jwkFile));
        } catch (ParseException e) {
            throw new OctopusConfigurationException(String.format("Parsing the JWK file failed with %s", e.getMessage()));
        }

        try {
            inputStream.close();
        } catch (IOException e) {
            throw new OctopusUnexpectedException(e);
        }

        return result;
    }

    public boolean existsApiKey(String apiKey) {
        return jwkSet.getKeyByKeyId(apiKey) != null;
    }

    public JWK getJWKForApiKey(String apiKey) {
        return jwkSet.getKeyByKeyId(apiKey);
    }

    public boolean hasSingleKey() {
        return jwkSet.getKeys().size() == 1;
    }

    public JWK getSingleKey() {
        return jwkSet.getKeys().iterator().next();
    }
}
