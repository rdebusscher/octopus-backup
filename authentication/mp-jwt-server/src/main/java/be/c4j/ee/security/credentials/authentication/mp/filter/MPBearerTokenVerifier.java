/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.c4j.ee.security.credentials.authentication.mp.filter;

import be.c4j.ee.security.credentials.authentication.mp.config.MPConfiguration;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.shiro.util.StringUtils;
import org.slf4j.Logger;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.Date;
import java.util.List;

/**
 * Verifies audience (from config) and expiration time from MicroProfile JWT Auth token.
 */
@ApplicationScoped
public class MPBearerTokenVerifier {

    @Inject
    private Logger logger;

    @Inject
    private MPConfiguration mpConfiguration;

    @PostConstruct
    public void init() {
        if (!StringUtils.hasText(mpConfiguration.getAudience())) {
            throw new OctopusConfigurationException("Parameter mp.aud is required");
        }
    }

    /**
     * Verifies if the header is valid according to MP JWT Auth spec.
     * See Minimum MP-JWT Required Claims.
     *
     * @param header
     * @return
     */
    public boolean verify(JWSHeader header) {
        boolean result = true;
        if (!JOSEObjectType.JWT.equals(header.getType())) {
            logger.error(String.format("Received an header typ which is not valid : %s", header.getType() == null ? "null" : header.getType().toString()));
            result = false;
        }
        if (!JWSAlgorithm.RS256.equals(header.getAlgorithm())) {
            logger.error(String.format("Received an algorithm which is not valid : %s", header.getAlgorithm() == null ? "null" : header.getAlgorithm().toString()));
            result = false;
        }
        return result;
    }

    /**
     * Verifies if the claimSet is valid according to MP JWT Auth spec.
     * See Minimum MP-JWT Required Claims.
     *
     * @param jwtClaimsSet
     * @return
     */
    public boolean verify(JWTClaimsSet jwtClaimsSet) {
        boolean result = true;
        if (!jwtClaimsSet.getAudience().contains(mpConfiguration.getAudience())) {
            logger.error(String.format("Received an Audience list which is not valid : %s", getAudienceList(jwtClaimsSet.getAudience())));
            result = false;
        }

        if (jwtClaimsSet.getExpirationTime() == null || jwtClaimsSet.getExpirationTime().before(new Date())) {
            logger.error(String.format("Received an invalid experation time  : %s", jwtClaimsSet.getExpirationTime()));
            result = false;
        }
        return result;
    }

    private String getAudienceList(List<String> audience) {
        StringBuilder result = new StringBuilder();
        for (String s : audience) {
            if (result.length() > 0) {
                result.append(", ");
            }
            result.append(s);
        }
        return result.toString();
    }
}
