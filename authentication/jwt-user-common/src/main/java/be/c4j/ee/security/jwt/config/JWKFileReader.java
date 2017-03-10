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
package be.c4j.ee.security.jwt.config;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import com.nimbusds.jose.jwk.JWK;

import javax.enterprise.context.ApplicationScoped;
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
public class JWKFileReader {

    /**
     * The default implementation doesn't  use the apiKey parameter. But custom specializations can use it
     * to read a JWK file based on the Client application which call us.
     *
     * @param apiKey
     * @param jwkFile
     * @return
     */
    public JWK readJWKFile(String apiKey, String jwkFile) {
        JWK result;
        InputStream inputStream = JWKFileReader.class.getClassLoader().getResourceAsStream(jwkFile);
        try {
            if (inputStream == null) {
                inputStream = new FileInputStream(jwkFile);
            }
            String content = new Scanner(inputStream).useDelimiter("\\Z").next();
            result = JWK.parse(content);
        } catch (FileNotFoundException e) {
            throw new OctopusConfigurationException("JWK File not found at " + jwkFile);
        } catch (ParseException e) {
            throw new OctopusConfigurationException("Parsing the JWK file failed with " + e.getMessage());
        }

        try {
            inputStream.close();
        } catch (IOException e) {
            throw new OctopusUnexpectedException(e);
        }

        return result;
    }
}